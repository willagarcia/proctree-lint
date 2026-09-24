use std::collections::HashMap;
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

fn run(path: &str) -> Result<Vec<Finding>, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
    let (processes, mut findings) = parse(&source);
    findings.extend(lint_duplicate_pids(&processes));
    findings.extend(lint_missing_parents(&processes));
    findings.extend(lint_zombies(&processes));
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
