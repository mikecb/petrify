//! Opening log files: plain or gzipped, single files, directories, or stdin.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;

use crate::events::{Error, Result};

const HEAD_BYTES: u64 = 16 * 1024;

/// One log that can be peeked at, then read from the start.
pub struct Input {
    pub name: String,
    data: Data,
}

enum Data {
    File(PathBuf),
    /// stdin cannot be rewound, so it is read once and replayed.
    Memory(Vec<u8>),
}

impl Input {
    pub fn open(&self) -> io::Result<Box<dyn BufRead + '_>> {
        match &self.data {
            Data::Memory(bytes) => Ok(Box::new(Cursor::new(bytes.as_slice()))),
            Data::File(path) => {
                let mut magic = [0u8; 2];
                let gzipped = File::open(path)?.read(&mut magic)? == 2 && magic == [0x1f, 0x8b];
                let file = File::open(path)?;
                Ok(if gzipped {
                    Box::new(BufReader::new(MultiGzDecoder::new(file)))
                } else {
                    Box::new(BufReader::new(file))
                })
            }
        }
    }

    /// The first few kilobytes, for format detection.
    pub fn head(&self) -> io::Result<String> {
        let mut bytes = Vec::new();
        self.open()?.take(HEAD_BYTES).read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// Resolve command-line arguments to inputs, walking directories (the shape
/// CloudTrail and flow logs are delivered to S3 in). `-` is stdin.
pub fn expand(paths: &[String]) -> Result<Vec<Input>> {
    let mut inputs = Vec::new();
    for raw in paths {
        if raw == "-" {
            let mut bytes = Vec::new();
            io::stdin().lock().read_to_end(&mut bytes)?;
            inputs.push(Input {
                name: "<stdin>".into(),
                data: Data::Memory(bytes),
            });
            continue;
        }
        let path = Path::new(raw);
        if path.is_dir() {
            let mut files = Vec::new();
            walk(path, &mut files).map_err(|e| Error(format!("{raw}: {e}")))?;
            inputs.extend(files.into_iter().map(file_input));
        } else if path.is_file() {
            inputs.push(file_input(path.to_path_buf()));
        } else {
            return Err(Error(format!("{raw}: no such file or directory")));
        }
    }
    Ok(inputs)
}

fn file_input(path: PathBuf) -> Input {
    Input {
        name: path.display().to_string(),
        data: Data::File(path),
    }
}

/// Every file below `dir`, in a stable order, skipping hidden entries.
fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries: Vec<PathBuf> = dir
        .read_dir()?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<io::Result<_>>()?;
    entries.sort();
    for path in entries {
        let hidden = path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.'));
        if hidden {
            continue;
        }
        if path.is_dir() {
            walk(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Run `each` on every line of `reader`, tolerating invalid UTF-8.
pub fn for_each_line(reader: &mut dyn BufRead, mut each: impl FnMut(&str)) -> io::Result<()> {
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        if reader.read_until(b'\n', &mut buffer)? == 0 {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&buffer);
        each(line.trim_end_matches(['\n', '\r']));
    }
}
