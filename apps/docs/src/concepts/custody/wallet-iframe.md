---
title: Wallet Iframe
---

# Wallet Iframe

The wallet iframe is the browser isolation boundary. It runs at a wallet origin
separate from the app origin and owns wallet UI, encrypted local records, worker
lifecycles, and wallet-origin session state.

## Boundary

| Boundary | Responsibility |
| --- | --- |
| App origin | Calls the SDK, renders app UI, and passes public operation inputs. |
| Wallet iframe origin | Owns wallet UI, wallet IndexedDB, auth-method flows, and workers. |
| Browser workers | Own hot holder material and operation-local secret state. |

App-origin JavaScript receives public results and non-secret flow state. Holder
shares, PRF output, Email OTP secret material, VoiceID templates, and server
shares stay outside the app origin. Exported key material reaches the app origin
only through a dedicated export flow.

## Why It Matters

The iframe keeps wallet authority independent from the app page. A compromised
app page still has to pass wallet-origin checks, policy, auth-method
requirements, Wallet Session admission, replay checks, and signing budget
admission before a signing lane can participate.
