#!/bin/bash
curl -si http://localhost/summary.php >/dev/null
curl -si -F "post=@large.bin;filename=large.bin"  http://localhost/summary.php?id=1 >/home/ubuntu/toolargebody_php1_php2.txt
curl -si -F "post=@large.bin;filename=large.bin"  http://localhost/index.html?id=2 >/home/ubuntu/toolargebody_html1_php2.txt
curl -0si http://localhost/virtual.php\?id=3 >/home/ubuntu/virtual.txt
curl -0si -F "post=@large.bin;filename=large.bin"  http://localhost/virtual.php\?id=4 >/home/ubuntu/toolargebody_virtual.php.txt
curl -0si http://localhost/simple.shtml\?id=5 > /home/ubuntu/shtml.txt
curl -0si -F "post=@large.bin;filename=large.bin" http://localhost/simple.shtml\?id=6 >/home/ubuntu/toolargebody_shtml.txt
./echos.sh bug.php bug.php >/home/ubuntu/pipeline.txt
./echos10.sh bug.php bug.php >/home/ubuntu/pipeline10.txt