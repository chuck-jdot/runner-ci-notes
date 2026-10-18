#!/bin/sh
# 诊断运行期间的保活助手:保持环境有持续活动。
i=0
while true; do
  i=$((i + 1))
  echo "warm $i $(date +%s)" >> /mnt/user-data/working/warm.txt
  sync
  stat /mnt/user-data/working/warm.txt >/dev/null 2>&1
  sh -c 'true' >/dev/null 2>&1
  sleep 2
done
