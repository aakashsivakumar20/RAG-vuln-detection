#!/usr/bin/env bash
# Rebuilds Report_Ch1-3_RAG_VulnDetection.docx from master_report.md + the chapter files.
# Requires: pandoc.
set -euo pipefail
cd "$(dirname "$0")"

python3 -c "
master = open('master_report.md').read()
ch1 = open('chapter1_introduction.md').read()
ch2 = open('chapter2_literature_review.md').read()
ch3 = open('chapter3_methodology.md').read()
master = master.replace('INSERT_CHAPTER_1', ch1).replace('INSERT_CHAPTER_2', ch2).replace('INSERT_CHAPTER_3', ch3)
open('.master_report_full.tmp.md','w').write(master)
"

pandoc .master_report_full.tmp.md -o Report_Ch1-3_RAG_VulnDetection.docx -V geometry:margin=1in
rm -f .master_report_full.tmp.md
echo "Built Report_Ch1-3_RAG_VulnDetection.docx"
