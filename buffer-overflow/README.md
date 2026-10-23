# Buffer Overflow and Return-to-libc: Exploitation and Defense

**Secure software development · C / Python · September 2026**

> A hands-on control-hijacking lab. I exploited a Set-UID root program with a
> classic stack buffer overflow to gain a root shell, then defeated a
> non-executable stack with a return-to-libc attack. The lab ran in a controlled
> VM with protections deliberately disabled; the write-up ends with the defenses
> that stop both attacks on a modern system.

> 📘 **Academic context.** Completed for a Secure Software Development course in my
> Computer Science degree (Cyber and Network Security concentration), on a
> deliberately vulnerable practice target in an isolated lab VM. The specific
> offsets and addresses from my exploit are left out; this documents the
> methodology and the defenses.

---

## Contents

- [The vulnerability](#the-vulnerability)
- [Lab setup](#lab-setup)
- [Attack 1 — stack buffer overflow](#attack-1--stack-buffer-overflow)
- [Attack 2 — return-to-libc](#attack-2--return-to-libc)
- [Why it only worked with protections off](#why-it-only-worked-with-protections-off)
- [Defenses](#defenses)
- [What I learned](#what-i-learned)
- [References](#references)

---

## The vulnerability

The target was `stack.c`, a small Set-UID **root** program that copies
attacker-controlled input into a fixed-size stack buffer without checking its
length. Because the program runs with root privileges, hijacking its execution
means running code as root.

The core mistake is an unbounded copy into a fixed buffer:

```c
char buffer[BUF_SIZE];
strcpy(buffer, user_input);   // no bounds check — input longer than the buffer
                              // overflows into adjacent stack memory
```

When the input is longer than the buffer, the extra bytes run past the buffer and
overwrite what sits beyond it on the stack — including the **saved return address**,
the value the CPU jumps to when the function finishes. Controlling that value means
controlling where the program goes next.

---

## Lab setup

The attacks below only work because the lab environment was intentionally weakened,
which matters for the defensive takeaway:

- **ASLR disabled** (`kernel.randomize_va_space = 0`) so stack addresses were
  predictable.
- **Non-executable-stack protection removed** for Attack 1 (and left on for Attack 2,
  which is the whole point of return-to-libc).
- **Stack canaries disabled** at compile time (`-fno-stack-protector`).
- **Set-UID root** on the vulnerable binary, so a hijack yields root.

> _[Screenshots to add: the commands disabling ASLR and compiling the target, and
> the resulting `#` root prompt from each attack.]_

---

## Attack 1 — stack buffer overflow

**Goal:** redirect execution into attacker-supplied instructions and spawn a root
shell.

**Approach (via `exploit.py`):**

1. **Find the offset.** Determine how many bytes of input sit between the start of the
   buffer and the saved return address — the distance the input has to travel before it
   can overwrite the return address. _[My offset: ____ bytes.]_
2. **Build the input layout.** Fill up to the return address, overwrite the return
   address with an address that lands inside attacker-controlled territory, and place
   the payload instructions where execution will land.
3. **Run the Set-UID binary with that input** and confirm a root shell.

**Result:** the program returned into the injected instructions instead of its normal
caller, producing a **root shell** (`#`). _[Screenshot: `whoami` → `root`.]_

---

## Attack 2 — return-to-libc

Attack 1 depends on executing instructions placed on the stack. The standard defense
against that is a **non-executable stack** — the CPU refuses to run code from stack
memory. Return-to-libc defeats that defense **without injecting any code at all.**

**Approach (via `exploit_libc.py` and `envaddr.c`):**

- Instead of pointing the return address at injected code, point it at a function that
  **already exists** in the C library, `system()`, and arrange the stack so its
  argument is the address of the string `"/bin/sh"`.
- `envaddr.c` was used to locate where that string lived in memory (it was placed in an
  environment variable, whose address is findable with ASLR off).
- When the vulnerable function returns, it "returns into libc" — it calls
  `system("/bin/sh")` using code that was always legitimately there.

**Result:** a **root shell**, with the stack never executing a single injected
instruction — which is exactly why a non-executable stack doesn't stop it.
_[Screenshot: root shell from the ret2libc run.]_

---

## Why it only worked with protections off

This is the most important part. Both attacks required a deliberately weakened system,
and each disabled protection maps to a real defense:

| What I disabled in the lab | What it represents in the real world |
|---|---|
| ASLR off | Modern systems randomize memory, so the addresses both attacks depend on aren't predictable |
| Non-executable stack off (Attack 1) | DEP/NX stops injected stack code from running |
| Stack canaries off | A canary value would have detected the overflow before the function returned |

Return-to-libc exists precisely because attackers adapted to non-executable stacks —
which is why defense can't rely on any single mitigation.

---

## Defenses

- **Safe coding first.** Use bounded functions (`strncpy`, `snprintf`) or safer
  languages; validate input length. The overflow never happens if the copy is bounded.
- **Stack canaries** (`-fstack-protector`) — a guard value placed before the return
  address; if an overflow changes it, the program aborts instead of returning.
- **Non-executable stack / DEP (NX)** — hardware-enforced refusal to execute stack
  memory, which stops code-injection overflows.
- **ASLR** (and building as a PIE) — randomizes stack, heap, and library addresses so
  the predictable addresses these attacks need aren't available.
- **`_FORTIFY_SOURCE=2`** — adds compile- and run-time bounds checks to common
  functions.
- **Drop privileges.** A program that doesn't need to stay root shouldn't; the damage
  from a hijack is bounded by what the process can do.

Modern systems ship most of these on by default, which is why these exact attacks are
teaching tools rather than everyday exploits — and why understanding them is really
about understanding the defenses.

---

## What I learned

- **An overflow is a control-flow problem, not just a crash.** Overwriting the saved
  return address turns "too much input" into "run my code."
- **Attackers adapt to defenses.** Return-to-libc exists because non-executable stacks
  closed the code-injection path, so the attack moved to code that was already present.
- **No single mitigation is enough.** Each protection I disabled blocks one path; real
  security comes from layering them.
- **Privilege matters.** The bug was dangerous because the program ran as root. Least
  privilege limits the blast radius of any hijack.

---

## References

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [Aleph One, "Smashing the Stack for Fun and Profit" (Phrack 49)](http://phrack.org/issues/49/14.html)
- [SEED Labs: Buffer Overflow and Return-to-libc](https://seedsecuritylabs.org/Labs_20.04/Software/)
