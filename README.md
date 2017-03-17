# Packets analyzer
An analyzer of packets to monitoring your interaction with your network. Work with libpcap (http://www.tcpdump.org/).

## Install
  - Clone or download.
  - Go in the folder project.
  - Make.
  - Execute and enjoy (./Analyseur.out)
  
libpcap is required.

## Parameters

| Parameters     |  Possible values | Description   | Incompatible with |
| -------------  | ---------------- | ------------- | ----------------- |
| -i | [interface]     | The interface you want to use  | -o      |
| -o     | [file]     | Use a file instead of an interface | -i      |
| -v     | 1,2 or 3     | The level of verbosity. Default: 3  |      |
| -f     | [filter]     | A filter (Example: -f "port 80")  |      |
| -c  | /     | Enable colorization  | -s   |
| -l  | [number]     | The number of packets you want to capture  |   |
| -s  | [file]     | Print the result into a file instead of the terminal |  -c |

## Screenshots

![Screen of the result with colorization](/screen1.png?raw=true "Colorization result")

![Screen of the result without colorization](/screen2.png?raw=true "Standard result")
