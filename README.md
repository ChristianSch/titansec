# Readme

```
████████╗██╗████████╗ █████╗ ███╗   ██╗
╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║
   ██║   ██║   ██║   ███████║██╔██╗ ██║
   ██║   ██║   ██║   ██╔══██║██║╚██╗██║
   ██║   ██║   ██║   ██║  ██║██║ ╚████║
   ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝
      >> Automated attack suite <<
```

Why another one of those? Why not metasploit or any of the others? Because I like to code stuff and it's a great learning experience. Also, metasploit ships a lot of irrelevant shit. The endgoal is to automate the assessment in the future.

## Usage
`go build .` to build the project. Run `./titan` to run it, use `<tab>` for help and auto completion. The first step would be to set the target variable used by all services: `set target $HOST`. Followed by an `enum os` and `enum services`. Browse discoveries via `disco`.

## Capabilities
- enumerate services and os of a target (using nmap)
- browse discoveries (information like os, services but also discovered vulns (via vulners script))
- basic ftp client

## Todo
- [ ] implement automated ftp user enum
- [ ] implement smb enum