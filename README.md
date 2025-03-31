# BoxDiff

## 💎 About

A simple, dependency free, Python script that gives you a "diff" of your box by showing you what was added, removed, 
or changed. It outputs the results to html.  
It just executes several powershell commands and directory listings.

It's designed, and meant to remain, simple and easy to maintain long term. No dependencies, no gui.  
Feel free to fork if you need major changes.

[Discord](https://discord.gg/2NCr2eSa)

## 📖 How to Use

```shell
# Data is written in your cwd. A container folder is helpful.
$ mkdir boxdiff
$ cd boxdiff
$ git clone git@github.com:boxdiff/boxdiff.git

# Default
$ python -m boxdiff
# Results in directory 'results_userName`. Open '0index.html'.

# With plugin
$ copy .\boxdiff\sample_plugin.py .\plugin.py
$ python -m boxdiff

# You can collect data from a different user.
# Also, run command prompt as Admin to get additional data
$ python -m boxdiff
$ python -m boxdiff Administrator
$ python -m boxdiff anotherUser
```

## 🛠️ Extendable

It's easily extendable while not complicating the main script.  
`sample_plugin.py` has different examples of what's possible.  
Copy `sample_plugin.py` as `plugin.py` and rerun.

## 💻 Cross Platform Support

None and not planned.

## 📜 License

MIT