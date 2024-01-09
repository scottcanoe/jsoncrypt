# jsoncrypt: encrypt/store and load/decrypt dictionaries.

**jsoncrypt** is a small module I created for use with another project. Basically,
it lets you easily dump a dictionary into an encrypted, password-protected file
which can later be loaded again using the same password. The only
dependency is [cryptography](https://github.com/pyca/cryptography).

### Example:
```python
import jsoncrypt

# Create and store some data.
dct = {'hello': 'world', 'pi': 3.14}
jsoncrypt.dump('somefile', 'password123', dct)

# Load it later.
d = jsoncrypt.load('somefile', 'password123')

```


