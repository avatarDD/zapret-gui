# zapret-gui
zapret2 web-gui for Keenetic, OpenWRT

Для запуска на роутерах Keenetic надо доустановить необходимое:
`opkg install python3-pip`
`pip3 install bottle && python3`

Склонировать данный реп, перейти в него и запустить:
`python3 app.py --port 8080`

В браузере открыть: `http://<ip_роутера>:8080/`
