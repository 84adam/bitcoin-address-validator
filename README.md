# Bitcoin address validator
Simple validation tool for bitcoin addresses.

## Supported currencies
| Currency      | Symbol | Mainnet | Testnet    | Note                                                                                                      |
|:-------------:| ------ | ------- | ---------- | ---------------------------------------------------------------------------------------------         |
| Bitcoin       | BTC    | +       | +          | P2PKH (Legacy Adresses), P2SH (Pay to Script Hash), P2WPKH (Native SegWit), P2TR (Taproot) address formats    |

## Usage
```python
from bitcoin_validate import is_valid_address

is_valid_address('bc1q7w9p2unf3hngtzmq3sq47cjdd0xd9sw7us5h6p')
```

## License
The Unlicense. See the LICENSE file for details.
