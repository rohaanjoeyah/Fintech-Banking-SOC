# FinTech SOC — Simulation & Attack Ground-Truth Report
Generated on: `2026-11-09T10:46:07.372992+00:00`

| Phase / Scenario | Start Timestamp (UTC) | End Timestamp (UTC) | Source IP | Target Account(s) | First Trace ID | Last Trace ID | Total API Calls |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Normal Baseline Traffic** | `2026-11-09T10:45:53.075403+00:00` | `2026-11-09T10:45:55.570553+00:00` | `Multiple Retail Pool (39.42.x.x, 103.215.x.x)` | 1004 - 1050 | `NRM-9BD4191D` | `NRM-07E3AEEB` | 32 |
| **Scenario 1: Credential Stuffing -> ATO -> $9,500 Wire Fraud** | `2026-11-09T10:45:55.570553+00:00` | `2026-11-09T10:45:57.149672+00:00` | `185.220.101.44` | user1001 (Account 1001 -> Mule 99990001) | `ATK1-5CFF50AD` | `ATK1-97CADA9D` | 34 |
| **Normal Baseline Traffic** | `2026-11-09T10:45:57.149672+00:00` | `2026-11-09T10:45:58.854826+00:00` | `Multiple Retail Pool (39.42.x.x, 103.215.x.x)` | 1004 - 1050 | `NRM-BE5234C8` | `NRM-66E6E735` | 23 |
| **Scenario 2: BOLA / IDOR Mass Account Enumeration** | `2026-11-09T10:45:58.854826+00:00` | `2026-11-09T10:46:01.984837+00:00` | `91.240.118.172` | Authenticated as 1015 -> Enumerated 1001..1050 | `ATK2-3F640A80` | `ATK2-B082746F` | 51 |
| **Normal Baseline Traffic** | `2026-11-09T10:46:01.984837+00:00` | `2026-11-09T10:46:03.671041+00:00` | `Multiple Retail Pool (39.42.x.x, 103.215.x.x)` | 1004 - 1050 | `NRM-41C27E7E` | `NRM-FF84B1B0` | 23 |
| **Scenario 3: AML Structuring ('Smurfing') & Velocity Drain** | `2026-11-09T10:46:03.671041+00:00` | `2026-11-09T10:46:05.263788+00:00` | `45.155.205.99` | user1002 (Account 1002 -> Mule 88887777) | `ATK3-F82AE8F6` | `ATK3-11FD0F34` | 13 |
| **Normal Baseline Traffic** | `2026-11-09T10:46:05.263788+00:00` | `2026-11-09T10:46:07.372992+00:00` | `Multiple Retail Pool (39.42.x.x, 103.215.x.x)` | 1004 - 1050 | `NRM-952F2027` | `NRM-3568F0D2` | 28 |
