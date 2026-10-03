-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Compile into the package-local .runtime/AUKORA Prime.app.
on run
    set bundlePath to POSIX path of (path to me)
    set runtimePath to do shell script "/usr/bin/dirname " & quoted form of bundlePath
    set desktopPath to do shell script "/usr/bin/dirname " & quoted form of runtimePath
    set launcherPath to desktopPath & "/Prime.command"
    set logPath to runtimePath & "/pilot-launch.log"
    do shell script "umask 077; /usr/bin/nohup /bin/zsh " & quoted form of launcherPath & " </dev/null >>" & quoted form of logPath & " 2>&1 &"
end run
