# qangr

qangr is a streamlined CLI tool (a wrapper for the Angr framework) designed to simplify and accelerate CTF challenge solving.

While Angr is a powerful and versatile framework, it can be overwhelming for beginners or impractical for quick tasks. qangr focuses on the essential features needed to reverse and analyze binaries, offering a simple and efficient CLI experience. It may not include all of Angr’s advanced capabilities, but it’s perfect for quickly pwning simple challenges in seconds.

# Install

Run these commands to quickly add it to your path.

```bash
git clone https://github.com/qvipin/qangr.git
cd qangr/
pip install -r requirements.txt
sudo cp qangr.py /usr/local/bin/qangr
qangr
```

# Usage

```txt
usage: qangr [-h] -g <0x00000> [-b <0x00000>] [-B <0x00000 or auto>] [--DFS] [--binary-info] [--angr-logging-level {DEBUG,INFO}] <binary>

A streamlined CLI tool (a wrapper for the Angr framework) designed to simplify and accelerate CTF challenge solving.

Made with ❤️ by qvipin

positional arguments:
  <binary>              Target Binary (e.g. chall or crackme)

options:
  -h, --help            show this help message and exit
  -g <0x00000>, --good-address <0x00000>
                        Good Address (Win Func)
  -b <0x00000>, --bad-address <0x00000>
                        Bad Address (e.g. puts(str: "Incorrect!"))
  -B <0x00000 or auto>, --base-address <0x00000 or auto>
                        Base Address; Use 0x400000 or Specify AUTO for PIE Binaries (Default is `0x000000`)
  --DFS                 Uses DFS exploration instead of the default BFS Exploration
  --binary-info         Specify argument for additional binary information.
  --angr-logging-level {DEBUG,INFO}
                        Logging level for angr (Default: WARNING and higher). Use --angr-logging-level=<value>
```

# Examples

See [this](https://www.vipin.xyz/blog/qangr-demo) blog for some qangr examples.

# License

Copyright (C) 2025 qvipin

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

