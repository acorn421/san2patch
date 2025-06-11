# gpt-4o-mini
python ./run.py Final run-patch 1 --experiment-name usenix_rq3_test_4o_mini --retry-cnt 1 --max-retry-cnt 1 --model gpt-4o-mini --version zeroshot --vuln-ids "CVE-2016-1839"

# gpt-3.5
python ./run.py Final run-patch 1 --experiment-name usenix_rq3_test_gpt_3.5 --retry-cnt 1 --max-retry-cnt 1 --model gpt-3.5 --version tot --vuln-ids "CVE-2016-1839"

# claude-3.5-sonnet
python ./run.py Final run-patch 1 --experiment-name usenix_rq3_test_claude_3.5_sonnet --retry-cnt 1 --max-retry-cnt 1 --model sonnet-3.5-sonnet --version tot --vuln-ids "CVE-2016-1839"

# gemini-1.5-pro
python ./run.py Final run-patch 1 --experiment-name usenix_rq3_test_gemini_1.5_pro --retry-cnt 1 --max-retry-cnt 1 --model gemini-1.5-pro --version tot --vuln-ids "CVE-2016-1839"

# gemini-1.5-flash
python ./run.py Final run-patch 1 --experiment-name usenix_rq3_test_gemini_1.5_flash --retry-cnt 1 --max-retry-cnt 1 --model gemini-1.5-flash --version tot --vuln-ids "CVE-2016-1839"