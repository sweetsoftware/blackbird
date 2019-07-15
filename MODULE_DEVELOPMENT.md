# Module folder structure

A module is a folder in the "blackbird/modules" directory.

It follows this structure:

```
<modulename>/
├── __init__.py
├── setup.sh
├── README.md
└── <any resource file(s)>
```

Modules are called on each port discovered for each target. Modules act at the **service/port** level.
Therefore, the module developer must define on which services the module is relevant (see below).

## \_\_init\_\_.py

This is the python code for the module.

### Module instance

The module must to be a **ModuleInstance** class inheriting from the **Module** class. 
The constructor of the **Module** class has to be called from the module as such:

```
from blackbird.core.module import Module


class ModuleInstance(Module):

    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)

```


### Module attributes

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

### Module methods



Three methods at least have to be defined in a **ModuleInstance** class:

* can_run(self)
* enum(self)
* brute(self)

The **can_run** method returns a boolean, indicating if the module is suited to be run on a particular service.
Indeed, it would not make sense to call an SSH bruteforce module on an FTP server.

Here is an example that will ensure the module is run only on SSH servers detected by nmap.

```
    def can_run(self):
        if self.proto == 'tcp' and self.service == 'ssh':
            return True
        return False
```

The **enum** method is called when the --enum flag is passed on the command line. It should perform various
enumeration operations, which are not too much time consuming.

```
def enum(self):
    utils.log("Performing quick enumeration on %s:%s ..." % (self.target, self.port))
    
    Checking some well-known config issue ...
    
    Extracting encryption certificates ...
    
    Grabbing a screenshot ...
```

The **brute** method is called when the --brute flag is passed on the command line. It should perform
lenghthy operations, such as all kinds of bruteforce.

```
    def brute(self):
        utils.log("Performing all kinds of lenthy bruteforce on %s:%s ..." % (self.target, self.port))
        
        Doing login/password bruteforce ...
        
        Checking default accounts ...
        
        URL bruteforce ...
        
        SID bruteforce ...
```

Helper methods are inherited from the **Module** class:

* **self.get_resource_path(filename)**: returns absolute path to a file stored in the module folder.
This must be used to reference any resource material included in the module folder, such as wordlists or scripts.

* **self.get_output_path(filename)**: returns absolute path to a file to be stored in the output folder.
This is used to store module output, such as logs and screenshots, without knowning in advance the full
output path.

Let's say we run a bruteforce tool in our **brute** method, with a wordlist included in the module 
and we want to store the result in the current scan directory.
The function would be like this:

```
def brute(self):
    utils.runcmd('bruteforcer %s %s --wordlist %s --output %s' %
        (self.target, self.port, 
            self.get_resource_path('wordlist.txt'), 
            self.get_output_path('bruteforce_output.txt')))
``` 

### utils.py

This contains utility procedures that can be used in modules.

```
from blackbird import utils
```

**utils.run_cmd** should be used to run system commands.

```
run_cmd(cmdline, timeout=None, shell=True, wdir=None)
```

* **timeout** is a number of seconds to wait for the process to complete (default: no timeout)
* **wdir** can be set to override the default process working directory

**utils.log** is used to print module output.

```
log(log_str, log_type='')
```

* **log_type** can be set to "info" to change the output color. Default is no color override.


## setup.sh

This is a shell script that installs module dependencies. This includes any third party tools, python
modules, and any setup needed by the module.

Example:
```
#!/bin/bash

# Install third-party tools
apt-get -yq update
apt-get -yq install chromium curl whatweb wfuzz hydra

# Any other setup instruction ...
```

## README.md

This is a plaintext file containing module documentation. It can provide the user with information about how
the module works and the output of the module.

# Example

Here is an example of an "hello world" module.

```
from blackbird import utils
from blackbird import config
from blackbird.core.module import Module


class ModuleInstance(Module):
    
    # Init module variables
    def __init__(self, target, port, service, nmap_results, output_dir, proto):
        Module.__init__(self, target, port, service, nmap_results, output_dir, proto)
        self.some_var = 1
    
    # Module should be run only on ssh services
    def can_run(self):
        if self.proto == 'tcp' and self.service == 'ssh':
            return True
        return False
    
    # Perform quick enumeration
    def enum(self):
        utils.log("Performing enumeration on %s:%s ..." % (self.target, self.port))
        utils.run_cmd('ls -alh /')
    
    # Perform bruteforce
    def brute(self):
        utils.log("Performing all kinds of lenthy bruteforce on %s:%s ..." % (self.target, self.port))
        utils.runcmd('bruteforcer %s %s --wordlist %s --output %s' %
        (self.target, self.port, 
            self.get_resource_path('wordlist.txt'), 
            self.get_output_path('bruteforce_output.txt'))) 
```

The module structure will look like this:

```
helloworld
├── __init__.py
├── setup.sh
├── README.md
└── wordlist.txt
```
