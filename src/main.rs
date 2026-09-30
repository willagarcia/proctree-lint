use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::process::ExitCode;

struct Process {
    pid: u32,
    ppid: u32,
    state: String,
    command: String,
    line: usize,
}

struct Finding {
    line: usize,
    rule: &'static str,
    message: String,
}

// Snapshot lines look like `pid ppid state command`, the same fields you get
// from `ps -eo pid,ppid,state,comm`. Blank lines and '#' comments are ignored
// so a snapshot can be captured, trimmed by hand, and checked in.
fn parse(source: &str) -> (Vec<Process>, Vec<Finding>) {
    let mut processes = Vec::new();
    let mut findings = Vec::new();

    for (idx, raw_line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 4 {
            findings.push(Finding {
                line: line_no,
                rule: "parse-error",
                message: format!(
                    "expected 'pid ppid state command', found {} field(s)",
                    tokens.len()
                ),
            });
            continue;
        }

        let pid = match tokens[0].parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                findings.push(Finding {
                    line: line_no,
                    rule: "parse-error",
                    message: format!("pid '{}' is not a non-negative integer", tokens[0]),
                });
                continue;
            }
        };
        let ppid = match tokens[1].parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                findings.push(Finding {
                    line: line_no,
                    rule: "parse-error",
                    message: format!("ppid '{}' is not a non-negative integer", tokens[1]),
                });
                continue;
            }
        };

        processes.push(Process {
            pid,
            ppid,
            state: tokens[2].to_string(),
            command: tokens[3..].join(" "),
            line: line_no,
        });
    }

    (processes, findings)
}

fn lint_duplicate_pids(processes: &[Process]) -> Vec<Finding> {
    let mut first_seen: HashMap<u32, usize> = HashMap::new();
    let mut findings = Vec::new();
    for p in processes {
        if let Some(&prev_line) = first_seen.get(&p.pid) {
            findings.push(Finding {
                line: p.line,
                rule: "duplicate-pid",
                message: format!("pid {} already defined on line {}", p.pid, prev_line),
            });
        } else {
            first_seen.insert(p.pid, p.line);
        }
    }
    findings
}

// A ppid of 0 is the kernel itself, and a process is allowed to be its own
// ppid in degenerate single-process snapshots. Anything else must point at a
// pid that also appears in the snapshot, or the tree can't be reconstructed.
fn lint_missing_parents(processes: &[Process]) -> Vec<Finding> {
    let known: HashMap<u32, ()> = processes.iter().map(|p| (p.pid, ())).collect();
    let mut findings = Vec::new();
    for p in processes {
        if p.ppid == 0 || p.ppid == p.pid {
            continue;
        }
        if !known.contains_key(&p.ppid) {
            findings.push(Finding {
                line: p.line,
                rule: "orphan-process",
                message: format!(
                    "pid {} ({}) has ppid {} which is not present in the snapshot",
                    p.pid, p.command, p.ppid
                ),
            });
        }
    }
    findings
}

fn lint_zombies(processes: &[Process]) -> Vec<Finding> {
    processes
        .iter()
        .filter(|p| p.state.starts_with('Z'))
        .map(|p| Finding {
            line: p.line,
            rule: "zombie-process",
            message: format!(
                "pid {} ({}) is a zombie; its parent never reaped it",
                p.pid, p.command
            ),
        })
        .collect()
}

// Follows ppid links upward from every pid. A self-parent is tolerated (see
// lint_missing_parents), so only loops of two or more processes count. Each
// cycle is reported once, on its earliest line. When a pid is duplicated the
// first definition wins, since duplicate-pid already flags the later ones.
fn lint_cycles(processes: &[Process]) -> Vec<Finding> {
    let mut parent: HashMap<u32, (u32, usize)> = HashMap::new();
    let mut order: Vec<u32> = Vec::new();
    for p in processes {
        if !parent.contains_key(&p.pid) {
            parent.insert(p.pid, (p.ppid, p.line));
            order.push(p.pid);
        }
    }

    let mut findings = Vec::new();
    let mut done: HashSet<u32> = HashSet::new();
    for &start in &order {
        if done.contains(&start) {
            continue;
        }
        let mut path: Vec<u32> = Vec::new();
        let mut position: HashMap<u32, usize> = HashMap::new();
        let mut cur = start;
        loop {
            if done.contains(&cur) {
                break;
            }
            if let Some(&i) = position.get(&cur) {
                let members = &path[i..];
                let line = members.iter().map(|pid| parent[pid].1).min().unwrap_or(0);
                let mut chain: Vec<String> = members.iter().map(|pid| pid.to_string()).collect();
                chain.push(members[0].to_string());
                findings.push(Finding {
                    line,
                    rule: "parent-cycle",
                    message: format!(
                        "{} processes are their own ancestors: {}",
                        members.len(),
                        chain.join(" -> ")
                    ),
                });
                break;
            }
            position.insert(cur, path.len());
            path.push(cur);
            match parent.get(&cur) {
                Some(&(ppid, _)) if ppid != 0 && ppid != cur => cur = ppid,
                _ => break,
            }
        }
        done.extend(path);
    }
    findings
}

fn run(path: &str) -> Result<Vec<Finding>, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
    let (processes, mut findings) = parse(&source);
    findings.extend(lint_duplicate_pids(&processes));
    findings.extend(lint_missing_parents(&processes));
    findings.extend(lint_zombies(&processes));
    findings.extend(lint_cycles(&processes));
    findings.sort_by_key(|f| f.line);
    Ok(findings)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        let prog = args.first().map(String::as_str).unwrap_or("proctree-lint");
        eprintln!("usage: {} <snapshot.ptree>", prog);
        return ExitCode::from(2);
    }

    let findings = match run(&args[1]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2);
        }
    };

    for f in &findings {
        println!("{}:{}: {}: {}", args[1], f.line, f.rule, f.message);
    }

    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cycles(source: &str) -> Vec<Finding> {
        let (processes, _) = parse(source);
        lint_cycles(&processes)
    }

    #[test]
    fn two_process_cycle_is_reported_once() {
        let found = cycles("1 0 S init\n10 20 S a\n20 10 S b\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2);
        assert_eq!(found[0].message, "2 processes are their own ancestors: 10 -> 20 -> 10");
    }

    #[test]
    fn descendants_of_a_cycle_are_not_members() {
        let found = cycles("10 20 S a\n20 10 S b\n30 10 S child\n");
        assert_eq!(found.len(), 1);
        assert!(found[0].message.starts_with("2 processes"));
    }

    #[test]
    fn self_parent_and_healthy_tree_are_clean() {
        assert!(cycles("5 5 S solo\n1 0 S init\n2 1 S child\n").is_empty());
    }

    #[test]
    fn separate_cycles_are_each_reported() {
        let found = cycles("1 2 S a\n2 1 S b\n3 4 S c\n4 5 S d\n5 3 S e\n");
        assert_eq!(found.len(), 2);
    }
}
