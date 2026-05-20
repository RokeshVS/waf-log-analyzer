#!/usr/bin/env python3
"""Sanity test for WAF Log Analysis API."""

import asyncio
import json
import logging
import sys

import httpx

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("sanity-test")

# API base URL
API_URL = "http://localhost:8000"

# Sample AWS WAF logs for testing
SAMPLE_LOGS = [
    {
        "timestamp": 1576280412771,
        "formatVersion": 1,
        "webaclId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/a1b2c3d4",
        "terminatingRuleId": "AWSManagedRulesCommonRuleGroup",
        "terminatingRuleType": "MANAGED_RULE_GROUP",
        "action": "BLOCK",
        "terminatingRuleMatchDetails": [
            {
                "conditionType": "CROSS_SITE_SCRIPTING",
                "sensitivityLevel": "HIGH",
                "location": "BODY",
                "matchedData": ["<script>", "alert"]
            }
        ],
        "httpSourceName": "-",
        "httpSourceId": "-",
        "ruleGroupList": [],
        "rateBasedRuleList": [],
        "nonTerminatingMatchingRules": [],
        "httpRequest": {
            "clientIp": "192.0.2.1",
            "country": "US",
            "headers": [
                {"name": "Host", "value": "example.com"},
                {"name": "User-Agent", "value": "curl/7.64.1"},
                {"name": "Accept", "value": "*/*"}
            ],
            "uri": "/admin",
            "args": "input=test",
            "httpVersion": "HTTP/1.1",
            "httpMethod": "POST",
            "requestId": "test-request-1"
        },
        "labels": []
    },
    {
        "timestamp": 1592361810888,
        "formatVersion": 1,
        "webaclId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/a1b2c3d4",
        "terminatingRuleId": "AWSManagedRulesSQLiRuleGroup",
        "terminatingRuleType": "MANAGED_RULE_GROUP",
        "action": "BLOCK",
        "terminatingRuleMatchDetails": [
            {
                "conditionType": "SQL_INJECTION",
                "sensitivityLevel": "HIGH",
                "location": "QUERY_STRING",
                "matchedData": ["1", "OR", "1=1"]
            }
        ],
        "httpSourceName": "-",
        "httpSourceId": "-",
        "ruleGroupList": [],
        "rateBasedRuleList": [],
        "nonTerminatingMatchingRules": [],
        "httpRequest": {
            "clientIp": "192.0.2.2",
            "country": "BR",
            "headers": [
                {"name": "Host", "value": "api.example.com"},
                {"name": "User-Agent", "value": "curl/7.64.1"},
                {"name": "Accept", "value": "*/*"}
            ],
            "uri": "/api/users",
            "args": "id=1",
            "httpVersion": "HTTP/1.1",
            "httpMethod": "GET",
            "requestId": "test-request-2"
        },
        "labels": []
    },
    {
        "timestamp": 1592361810889,
        "formatVersion": 1,
        "webaclId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/a1b2c3d4",
        "terminatingRuleId": "AWSManagedRulesXSSRuleGroup",
        "terminatingRuleType": "MANAGED_RULE_GROUP",
        "action": "BLOCK",
        "terminatingRuleMatchDetails": [
            {
                "conditionType": "CROSS_SITE_SCRIPTING",
                "sensitivityLevel": "MEDIUM",
                "location": "HEADER",
                "matchedData": ["<img", "onerror"]
            }
        ],
        "httpSourceName": "-",
        "httpSourceId": "-",
        "ruleGroupList": [],
        "rateBasedRuleList": [],
        "nonTerminatingMatchingRules": [],
        "httpRequest": {
            "clientIp": "10.0.0.1",
            "country": "CN",
            "headers": [
                {"name": "Host", "value": "internal.example.com"},
                {"name": "User-Agent", "value": "Mozilla/5.0"},
                {"name": "X-Forwarded-For", "value": "10.0.0.1"}
            ],
            "uri": "/search",
            "args": "q=test",
            "httpVersion": "HTTP/1.1",
            "httpMethod": "GET",
            "requestId": "test-request-3"
        },
        "labels": []
    }
]


async def test_health() -> bool:
    """Test the health endpoint."""
    logger.info("=== Testing Health Endpoint ===")
    try:
        async with httpx.AsyncClient() as client:
            # Log request
            logger.info("="*80)
            logger.info("REQUEST (INPUT TO API)")
            logger.info("="*80)
            logger.info(f"GET {API_URL}/health")
            logger.info("="*80 + "\n")
            
            response = await client.get(f"{API_URL}/health", timeout=10.0)
            
            # Log response
            logger.info("="*80)
            logger.info("RESPONSE (OUTPUT FROM API)")
            logger.info("="*80)
            logger.info(f"Status: {response.status_code}")
            data = response.json()
            logger.info(f"Response Body:")
            logger.info(json.dumps(data, indent=2))
            logger.info("="*80 + "\n")
            
            if response.status_code == 200 and data.get("status") == "ok":
                logger.info("✓ Health check passed\n")
                return True
            else:
                logger.error("✗ Health check failed\n")
                return False
    except Exception as e:
        logger.error(f"✗ Health check error: {e}\n")
        return False


async def test_batch_rca() -> bool:
    """Test batch RCA processing with multiple valid logs."""
    logger.info("=== Testing Batch RCA Processing (Complete Lifecycle) ===")
    
    # Use all 3 logs for batch processing
    test_logs = SAMPLE_LOGS
    logger.info(f"Submitting batch of {len(test_logs)} valid WAF logs...\n")
    
    try:
        payload = {
            "logs": test_logs,
            "context": "Production incident - analyzing multiple blocked requests"
        }
        
        # Log request payload
        logger.info("="*80)
        logger.info("REQUEST PAYLOAD (INPUT TO API)")
        logger.info("="*80)
        logger.info(f"POST {API_URL}/get-rca")
        logger.info(f"Content-Type: application/json")
        logger.info(f"\nRequest Body:")
        logger.info(json.dumps(payload, indent=2))
        logger.info("="*80 + "\n")
        
        async with httpx.AsyncClient() as client:
            logger.info("Sending batch request to /get-rca endpoint...")
            response = await client.post(
                f"{API_URL}/get-rca",
                json=payload,
                timeout=600.0  # 10 minutes for batch processing
            )
            
            logger.info(f"\nStatus: {response.status_code}")
            
            # Log response payload
            logger.info("="*80)
            logger.info("RESPONSE PAYLOAD (OUTPUT FROM API)")
            logger.info("="*80)
            logger.info(f"HTTP Status: {response.status_code}")
            logger.info(f"Content-Type: {response.headers.get('content-type', 'N/A')}")
            
            data = response.json()
            logger.info(f"\nResponse Body:")
            logger.info(json.dumps(data, indent=2))
            logger.info("="*80 + "\n")
            
            logger.info(f"\nBatch Processing Summary:")
            logger.info(f"  - Status: {data.get('status')}")
            logger.info(f"  - Total Logs Submitted: {data.get('total_logs')}")
            logger.info(f"  - Successfully Analyzed: {data.get('successful')}")
            logger.info(f"  - Failed: {data.get('failed')}")
            
            # Check analyses
            analyses = data.get("analyses", [])
            if analyses:
                logger.info(f"\n=== Detailed RCA Results ({len(analyses)} logs analyzed) ===")
                for analysis in analyses:
                    logger.info(f"\nLog #{analysis['log_index']+1}:")
                    logger.info(f"  Rule Triggered: {analysis['rule_id']}")
                    logger.info(f"  Action: {analysis['action']}")
                    logger.info(f"  Root Cause Analysis:")
                    # Split long analysis into readable lines
                    for line in analysis['analysis'].split('\n')[:5]:
                        if line.strip():
                            logger.info(f"    {line}")
                    if len(analysis['analysis'].split('\n')) > 5:
                        logger.info(f"    ...")
            
            # Check errors
            errors = data.get("errors", [])
            if errors:
                logger.warning(f"\nProcessing Errors ({len(errors)}):")
                for error in errors:
                    logger.warning(f"  - {error}")
            
            logger.info("")
            
            # Success if at least some logs were analyzed successfully
            if response.status_code == 200 and data.get("status") in ["success", "partial"]:
                if len(analyses) > 0:
                    logger.info(f"✓ Batch RCA test passed - {len(analyses)}/{len(test_logs)} logs analyzed\n")
                    return True
                else:
                    logger.error("✗ No analyses returned\n")
                    return False
            else:
                logger.error(f"✗ Batch RCA test failed with status {response.status_code}\n")
                return False
                
    except Exception as e:
        logger.error(f"✗ Batch RCA error: {e}\n")
        import traceback
        traceback.print_exc()
        return False


async def test_invalid_logs() -> bool:
    """Test error handling with invalid logs."""
    logger.info("=== Testing Error Handling ===")
    logger.info("Submitting invalid logs to test validation...\n")
    
    invalid_logs = [
        {"incomplete": "log"},  # Missing required fields
        "invalid json {",  # Malformed JSON
        {"action": "BLOCK"},  # Missing required fields
    ]
    
    try:
        payload = {
            "logs": invalid_logs,
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{API_URL}/get-rca",
                json=payload,
                timeout=10.0
            )
            
            logger.info(f"Status: {response.status_code}")
            
            # Should fail because no valid logs
            if response.status_code == 400:
                logger.info(f"Response: {response.json()}")
                logger.info("✓ Invalid logs correctly rejected\n")
                return True
            else:
                logger.warning(f"⚠ Unexpected status code: {response.status_code}")
                logger.warning(f"Response: {response.json()}\n")
                return False
                
    except Exception as e:
        logger.warning(f"⚠ Error handling test inconclusive: {e}\n")
        return False


async def test_rule_docs() -> bool:
    """Test the /rule-docs endpoint for a known rule ID."""
    logger.info("=== Testing Rule Docs Endpoint ===")
    rule_id = "AWSManagedRulesCommonRuleGroup"
    try:
        async with httpx.AsyncClient() as client:
            logger.info("="*80)
            logger.info("REQUEST (INPUT TO API)")
            logger.info("="*80)
            logger.info(f"GET {API_URL}/rule-docs/{rule_id}")
            logger.info("="*80 + "\n")

            response = await client.get(f"{API_URL}/rule-docs/{rule_id}", timeout=60.0)

            logger.info("="*80)
            logger.info("RESPONSE (OUTPUT FROM API)")
            logger.info("="*80)
            logger.info(f"Status: {response.status_code}")
            data = response.json()
            # Truncate docs for readability
            display = dict(data)
            if "docs" in display and len(display["docs"]) > 300:
                display["docs"] = display["docs"][:300] + "…"
            logger.info(f"Response Body:\n{json.dumps(display, indent=2)}")
            logger.info("="*80 + "\n")

            if response.status_code == 200 and data.get("rule_id") == rule_id:
                logger.info("✓ Rule docs test passed\n")
                return True
            else:
                logger.error("✗ Rule docs test failed\n")
                return False
    except Exception as e:
        logger.error(f"✗ Rule docs error: {e}\n")
        return False


async def main():
    """Run all tests."""
    logger.info("\n" + "="*60)
    logger.info("WAF Log Analysis API - Sanity Test")
    logger.info("="*60 + "\n")

    results = {}

    # Test health endpoint
    results["health"] = await test_health()

    # Test rule docs lookup
    results["rule_docs"] = await test_rule_docs()

    # Test batch RCA processing with multiple valid logs
    results["batch_rca"] = await test_batch_rca()

    # Test error handling
    results["error_handling"] = await test_invalid_logs()

    # Summary
    logger.info("="*60)
    logger.info("Test Summary")
    logger.info("="*60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{test_name:30s} {status}")

    logger.info("="*60)
    logger.info(f"Overall: {passed}/{total} tests passed\n")

    return all(results.values())


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)