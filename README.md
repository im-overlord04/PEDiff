# PEDiff
Tool for comparing bytes and structural components of two PE files


## Installation

```bash
docker build . -t pediff
```

## Usage

In the following examples, users must specify only the parameters surrounded by `<>`.

For comparing two files:
```bash
docker run -v <path/to/file_1>:/<file_1> -v <path/to/file_2>:/<file_2> -v <path/to/output/folder/>:/tmp pediff -f /<file_1> /<file_2> -o /tmp/<output_name.csv>
```
For comparing all the files in a directory:

```bash
docker run -v <path/to/directory/>:/input -v <path/to/output/folder/>:/tmp pediff -d /input -o /tmp/<output_name.csv> -p <number_of_processes>
```

N.B: TLSH is not always able to compute the fingerprint for a given feature (usually due to very small sizes) and assigns as fingerprint `TNULL`.
A comparison between two features where at least one of them is TNULL results in an error and the distance -1 is assigned.

The option `--print` eventually prints in stdout the results of the comparison. In case of the option `--directory` is specified, the comparisons are aggregated as it follows:
- if the compared feature is a hash, it prints the percentage of matching comparisons;
- it is TLSH, the failed comparisons are filtered out (i.e. comparisons with distance -1) and the mean value of the remaining ones is shown (in case all the comparisons failed, -1 is the assigned value)
