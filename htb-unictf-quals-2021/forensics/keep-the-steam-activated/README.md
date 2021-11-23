### Keep the steam activated

In this challenge, we were provided a pcap file and were expected to investigate the traffic.

On the first stream(20) we see a reverse shell interaction.
![](https://i.imgur.com/GioWmlV.png)


The attacker after getting reverse shell as user smith, executes commands to dump the `ntds.dit` and `SYSTEM`(stream 21)

![](https://i.imgur.com/g7X6ZoB.png)

![](https://i.imgur.com/EgB2Xls.png)


On the following 23rd and 24th streams we see that base64 encoded files with certutil are getting transfered using netcat
![](https://i.imgur.com/ioReYyP.png)

![](https://i.imgur.com/70CoLH6.png)


![](https://i.imgur.com/KjS5YiV.png)


We can extract those and verify them using file command.
![](https://i.imgur.com/gIaVytI.png)

The attacker then starts a winrm session with administrator user. It is very obvious at this point that attacker dumped the hashes from the files obtained before and took over the administrator's account. We can also save this traffic to another pcap file so working on it later on would be easy
![](https://i.imgur.com/Q6ZgvAP.png)


Let's do the same thing with attacker.

![](https://i.imgur.com/ffNqZ3t.png)


It looks like Administrator's password is empty so there is a high chance that the attacker used PTH.
![](https://i.imgur.com/uRzSgeZ.png)


I used [winrm_decrypt.py](https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045#file-winrm_decrypt-py) to decrypt the traffic


```
python3 winrm_decrypt.py --hash '8bb1f8635e5708eb95aedf142054fc95' winrm.pcap > stream.txt
```

![](https://i.imgur.com/IWEnXku.png)

We can now grep base64 encoded `HTB{` in the traffic.


![](https://i.imgur.com/2OJFZnW.png)

`HTB{n0th1ng_1s_tru3_3v3ryth1ng_1s_d3crypt3d}`

