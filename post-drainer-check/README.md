# Post-drainer wallet check (read-only)

A small `cast` script for the first ten minutes after a wallet drainer. It doesn't sign or send anything. It tells you:

1. whether the address has an active EIP-7702 delegation (code starting `0xef0100`), and to which contract
2. the plain ERC-20 allowance for a token/spender pair
3. the Permit2 allowance for the same pair, plus whether Permit2 itself is approved on the token
4. whether an NFT operator still has `setApprovalForAll`
5. the ETH balance, as a reminder that a sweeper will take any gas you send

Order matters: if a 7702 delegation is active, clear that before spending gas on token revokes.

```
RPC=https://your-rpc ./post-drainer-check.sh 0xWallet 0xToken 0xSpender 0xNFT 0xOperator
```

Longer write-ups from MEV DAO: [which approvals to revoke after a drainer](https://mevdao-org.github.io/approvals-after-a-drainer.html), [how to revoke token approvals and Permit2 signatures](https://mevdao.org/blog/how-to-revoke-token-approvals-and-permit2-signatures), [how to check and remove a malicious EIP-7702 delegation](https://mevdao.org/blog/how-to-check-and-remove-a-malicious-eip-7702-delegation), and if the key itself leaked, [EIP-7702 sweeper rescue](https://mevdao.org/blog/rescue-tokens-from-a-compromised-wallet-sweeper-bot-rescue-service).
