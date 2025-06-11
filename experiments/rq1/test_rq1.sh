# zeroshot
python ./run.py Final run-patch 1 --experiment-name usenix_rq1_test_zeroshot --retry-cnt 1 --max-retry-cnt 1 --model gpt-4o --version zeroshot --vuln-ids "CVE-2016-1839"

# cot
python ./run.py Final run-patch 1 --experiment-name usenix_rq1_test_cot --retry-cnt 1 --max-retry-cnt 1 --model gpt-4o --version cot --vuln-ids "CVE-2016-1839"

# no_context
python ./run.py Final run-patch 1 --experiment-name usenix_rq1_test_no_context --retry-cnt 1 --max-retry-cnt 1 --model gpt-4o --version no_context --vuln-ids "CVE-2016-1839"

# tot
python ./run.py Final run-patch 1 --experiment-name usenix_rq1_test_tot --retry-cnt 1 --max-retry-cnt 1 --model gpt-4o --version tot --vuln-ids "CVE-2016-1839"