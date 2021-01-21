Terraform Provider for Aqua Security
======================================
- Website: https://www.terraform.io
- [![Gitter chat](https://badges.gitter.im/hashicorp-terraform/Lobby.png)](https://gitter.im/hashicorp-terraform/Lobby)
- Mailing list: [Google Groups](http://groups.google.com/group/terraform-tool)

Requirements
------------

- [Terraform](https://www.terraform.io/downloads.html) 0.11.x or higher
- [Go](https://golang.org/doc/install) 1.12 or higher (to build the provider plugin)

Building the Provider
---------------------

Clone repository to: `$GOPATH/src/github.com/terraform-providers/terraform-provider-aqua`

```sh
$ mkdir -p $GOPATH/src/github.com/terraform-providers; cd $GOPATH/src/github.com/terraform-providers
$ git clone https://github.com/BryanKMorrow/terraform-provider-aqua
```

Enter the provider directory and build the provider

```sh
$ cd $GOPATH/src/github.com/terraform-providers/terraform-provider-aqua
$ make install
```
# Author
[Bryan Morrow](https://github.com/BryanKMorrow) (BryanKMorrow)  

# Disclaimer
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
