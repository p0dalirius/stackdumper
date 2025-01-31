![](./.github/banner.png)

<p align="center">
    A python tool to autmatically dump the stack content with a format string vulnerability in CTF.
    <br>
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/stackdumper">
    <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
    <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
    <br>
    <i>He pwn, He hak, he dumps the stak</i>
</p>

## Features

- [x] Exploit a format string vulnerability to dump the stack content.
- [x] Export results in CSV with `--csv <file.csv>`.

## Demonstration



## Usage

```
$ ./stack_dumper.py -h
usage: stack_dumper.py [-h] [-q] [-c CSV]

options:
  -h, --help         show this help message and exit
  -q, --quiet        Quiet output
  -c CSV, --csv CSV  Exports findings to CSV file.
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.