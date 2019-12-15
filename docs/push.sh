spawn git push
expect "Username"
send "$(https_user)\n"
expect "Password"
send "$(https_password)\n"
interact
set timeout 30