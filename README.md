# PEDiff
Tool for comparing bytes and structural components of two PE files


## Installation

```bash
docker build . -t overlord:pediff
```

## Usage

In the following examples, users must specify only the parameters surrounded by `<>`.

For comparing two files:
```bash
docker run -v <path/to/file_1>:/file_1 -v <path/to/file_2>:/file_2 -v <path/to/output/folder/>:/tmp overlord:pediff -f /file_1 /file_2 -o <output_name.csv>
```
For comparing all the files in a directory:

```bash
docker run -v <path/to/directory/>:/input -v <path/to/output/folder/>:/tmp overlord:pediff -d /input -o /tmp/<output_name.csv> -p <number_of_processes>
```