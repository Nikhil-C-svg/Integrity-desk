# Integrity Desk

A small Windows file integrity checker written in C++17. It saves SHA-256 hashes for files in a folder, then compares them with a later scan. The HTML report shows which files were added, changed, removed, or left unchanged.

Open [index.html](index.html) in a browser to try the report with sample data.

## Build

From the repository folder, run these commands in PowerShell with CMake and the Visual Studio C++ Build Tools installed.

~~~powershell
cmake -S . -B build
cmake --build build --config Release
$exe = ".\build\Release\integrity-desk.exe"
~~~

If you use MinGW-w64, you can compile directly:

~~~powershell
g++ -std=c++17 -O2 -municode integrity-desk.cpp -o integrity-desk.exe -lbcrypt
$exe = ".\integrity-desk.exe"
~~~

## Try it

~~~powershell
New-Item -ItemType Directory -Path demo-files
Set-Content .\demo-files\access.ini 'mode=read'
& $exe snapshot .\demo-files .\demo.baseline

Set-Content .\demo-files\access.ini 'mode=write'
Set-Content .\demo-files\notes.txt 'Change review'
& $exe audit .\demo-files .\demo.baseline .\index.html .\demo-report.html
Start-Process .\demo-report.html
~~~

The report shows one modified file and one added file. Click **View** beside a file to see its hashes. Use fresh output names when repeating the demo because existing baseline and report files are protected from overwrites.

The C++ scanner runs on Windows and uses CNG for SHA-256. The browser report runs offline. Keep the baseline outside the scanned folder and limit who can edit it, since the comparison trusts the hashes stored there.

Run the smoke test after building:

~~~powershell
.\smoke-test.ps1 -Exe $exe
~~~
                                                                                                                                               