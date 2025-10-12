savedcmd_awdog.mod := printf '%s\n'   awdog.o | awk '!x[$$0]++ { print("./"$$0) }' > awdog.mod
