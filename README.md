# Confluence Memory Web Shell
Confluence uses Apache Tomcat as its application server, so we will be able to use create a memory web shell by modifying its servlet applications to create a new path. Using the new path, we will be able to visit the path to execute arbitrary commands.

Apart from that, we are using java.lang.reflect methods to load classes into the memory during runtime to avoid detection

# Usage
- Compile the binaries
```
mvn clean && mvn package
```
- Execute arbitrary code
```
python3 script.py --url <base url of confluence> --key <secret key deefined in the code>
```
# Disclaimer
Any actions and or activities related to the material contained within this repository is provided "as is" without any warranty, express or implied. The author of this repository and/or any other related repositiories disclaims any liability for damages, including but not limited to direct, indirect or consequential damages arising out of the use or inability to use this code. The author does not guarantee the accuracy, reliability, or completeness of the code and shall not be held responsible for any errors, omissions, or any loss resulting from the use of this code. 

Any actions and or activities related to the material contained within this repository is solely your responsibility. The misuse of the tools in this repo could result in criminal charges being brought against the person(s) question. The author will not be held responsible in the event any criminal charges are brought against any individual(s) misusing the tools in this repository for malicious purposes or to break the law. In addition, the author disclaims any responsibility for any misuse of related code found in this repository.

# Acknowledgements
https://github.com/aaaademo/Confluence-EvilJar
