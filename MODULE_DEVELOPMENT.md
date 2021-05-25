# Blackbird module engine

Modules are stored in the **blackbird/modules** directory.

Modules are called on each port discovered for each target. Modules act at the **service/port** level.
Therefore, the module developer must define on which services the module is relevant (see below).

* Modules are always run against every open port on all targets found.
* The can_run() method is run and checks if the module is suited to be run on this port/service (e.g don't run an SSH bruteforce if the service is HTTP).
* If the module can run on the target port, the run() method is then called.


## Module source file

This is the python code for the module.

The module file should be under **blackbird/modules/somemodulename.py**.

Below is the minimal code for a "Hello World" module (save this as balckbird/modules/hello.py):

```
from blackbird import utils
from blackbird import config
from blackbird.core.module import Module


class ModuleInstance(Module):

    def can_run(self):
        return True

    async def run(self):
        utils.log('Running hello world module against %s:%s' % (self.target, self.port), 'info')

```

Output should be similar to:

```
blackbird -t 192.168.254.0/24 

...

[*] Running hello module ...
[*] Running hello world module against 192.168.254.140:135
[*] Running hello world module against 192.168.254.140:139
[*] Running hello world module against 192.168.254.140:445
[*] Running hello world module against 192.168.254.132:53
[*] Running hello world module against 192.168.254.142:22
[*] Running hello world module against localhost:22
[*] Running hello world module against localhost:5432
[*] Running hello world module against 192.168.254.131:22
```

## Module attributes

The following attributes are defined by default in the **Module** class.

* **self.target**: the ip address or hostname (if any) of the target on which the module is run

* **self.port**: the TCP/UDP port on which the module is run

* **self.service**: service type as detected by nmap (see nmap-services file), e.g 'ssh', 'http', 'ftp' etc.

* **self.proto**: service protocol, e.g 'tcp' or 'udp'

* **self.product**: "product" attribute in nmap XML, e.g "OpenBSD or Solaris rlogind"

* **self.version**: "version" attribute in nmap XML, e.g "9.4.2"

* **self.extrainfo**: "extrainfo" attribute in nmap XML, e.g "workgroup: WORKGROUP"

* **self.tunnel**: "tunnel" attribute in nmap XML, value can be "ssl" or empty "".

* **self.servicefp**: "servicefp" attribute in nmap XML, value can be any kind of 
data returned by the service.

These values are directly mirrored from nmap XML output. To know more about them, you can check the nmap XML
output DTD here: https://nmap.org/book/nmap-dtd.html

### Module tags

In addition, each module should be assigned a tag (when running blackbird with the -M option, which runs specific modules/tags).

By default, moduels have the tag "default", which means they always run unless otherwise specified:

```
class Module:
    # module tag e.g default, brute, extra
    TAGS = ["default",]
```

To add additional tags or remove the default tag, just override the TAGS class attribute.

Here, default tag is removed so the module will only run if **-M brute** or **-M http** is set on the command line, or if the module itself is called explicitly (**-M modulename**)

```
class ModuleInstance(Module):
    TAGS = ["brute","http"]
```

## Module methods

The following methods are defined in the **Module** class.

### can_run(self)

Should be overriden to return True if the module should run given the port/protocol/additional checks. Otherwise should return False.

Example:
```
# Run module only on tcp port flagged as ssh by nmap
def can_run(self):
    if self.proto == 'tcp' and self.service == 'ssh':
        return True
    return False
```

### async def run(self):

Should be overriden to implement module logic (running commands, performing attacks etc).

Example: 

```
async def run(self):
    utils.log('Running my module against %s:%s' % (self.target, self.port), 'info')
    # module logic ...
```

### get_resource_path(self, filename)

If the module needs external files (such as wordlist), the standard procedure is to put them in the **resources** directory (**blackbird/modules/resources**) and access them by calling this method.

Example: 

```
async def run(self):
    # module logic ...
    # get the full path to <blackbird_dir>/modules/resources/ssh-usernames.txt
    user_list = self.get_resource_path('ssh-usernames.txt')
    # Example : run command with user_list as argument ...
    wait utils.run_cmd("bruteforce.sh --wordlist {} --host {} --port {}".format(user_list, self.target, self.port))
```

### get_output_path(self, filename)

Returns the absolute path to the module output dir (within the blackbird instance working directory). When a module needs to output data, first get the output path by calling this method. Then write to the file. The file will be stored in the correct host and port folder at runtime.

Example:

```
async def run(self):
    utils.log('Running my module against %s:%s' % (self.target, self.port), 'info')
    ... module logic ...
    output_file = self.get_output_path('my_module_output.log')
    with open(output_file, 'w') as out:
        out.write('blah')
```

### Module contructor

The constructor does not need to be overriden but in case you want to perform actions on module instanciation or create a module subclass, then you should call the main contructor first:

```
 class HttpModule(Module):
    # Load module with target and service info
    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)
        # Perform additional actions
```

Module subclasses exist and can implement specific methods. For example, HttpModule implements HTTP related methods.

## Utility functions

Utility functions are defined in the **utils** modules and can be called from modules.

### utils.log

Print something to the main logfile:

```
utils.log("Hello", "info")
utils.log("Hello", "warning")
utils.log("Hello", "error")
utils.log("Hello") # no formatting
```

### utils.run_cmd

Run an external command or tool (async).

By default, output is printed to the log file (unless print_output=False is passed). Additional operations (e.g store to a file) can be done by retreiving the return value of run_cmd which is the raw command output.

```
output = wait utils.run_cmd("ls -alh")
# do something with cmd output
```

A timeout can be set (default is 15minutes).

This will abort run_cmd after 5 seconds and print a warning message indicating command timed out.

```
wait utils.run_cmd("sleep 1000", timeout=5)
```

