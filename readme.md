# SOLAR_PTS_Mon_opensource

Скрипт на python3 и шаблон Zabbix 4.2 для мониторинга состояния задач в Positive Technologies Max Patrol SIEM  
Поддерживаются версии PT SIEM:  
* 19.1
* 21.1 (не тестировалось)
* 22.0  

Решение позволяет мониторить состояние задач сбора данных PT SIEM и, при появлении проблем, выполнять автоматический перезапуск.
## Getting Started

Шаблон и скрипт предназначены для работы через элемент данных типа [внешние проверки](https://www.zabbix.com/documentation/4.0/ru/manual/config/items/itemtypes/external).  
Скрипт располагается на сервере zabbix или zabbix proxy. Пароли хранятся в конфиге в зашифрованном виде рядом со скриптом. Ключ шифрования хранится в файле loader.py. В разделе Build инструкция по замене ключа.  
**ВАЖНО!** Обязательно замените ключ шифрования! Использование текущего ключа шифрования означает автоматическую компроментацию вашей системы т.к. он находится в открытом доступе.
### Prerequirements

* Zabbix server(and/or proxy) 4.2 или выше
* Python3.5 и выше на сервере заббикс(или прокси)
* пакаджи для питона: cffi, ctyptography, pycparser, six, certifi (перечислены в файле requirements.txt)
* cpython, gcc и make
* учетная запись в интерфейс PT SIEM с доступом к списку задач и с возможностью запускать и останавливать задачи
* От сервера zabbix до сервера PT SIEM Core должны быть открыты порты:
  * TCP: any → 3333
  * TCP: any → 3334
  * TCP: any → 443

### Build
* Вы можете использовать распростаняемые нами бинарные сборки. Однако, в них зашит ключ шифрования, поэтому их использование рекомендуется исключительно в тестовой среде.
* Заменить ключ шифрования можно в строке 33 файла pyptsiem4/loader.py. Ключ должен быть набором байт. Проще всего получить ключ, вызвав python3 и выполнив
```
>>> import os
>>> os.urandom(32)
```
* Установить python3 (если не установлен), gcc и make
* Установить необходимые библиотеки python3
```
pip install -r requirements.txt
```
* выполнить сборку и установку
```
make install
```
* путь установки (по умолчанию путь внешних скриптов заббикс) - /usr/lib/zabbix/externalscripts
* если сборка производится не на сервере заббикс/заббикс прокси, то можно выполнить сборку в архив, архив перенести на сервер zabbix/zabbix proxy и распаковать в директорию /usr/lib/zabbix/externalscripts
```
make package
```

### Installing

**0.** Файлы скрипта (mpszabbix.py) необходимо разместить на сервере или прокси Zabbix в директории внешних скриптов Zabbix, по умолчанию это:  
````
/usr/lib/zabbix/externalscripts
````
**1.** Назначить файл mpszabbix.py исполняемым:
````
[root@zbx.proxy externalscripts]# pwd 
/usr/lib/zabbix/externalscripts
[root@zbx.proxy externalscripts]# chmod +x /usr/lib/zabbix/externalscripts/mpszabbix.py
````

**2.** Далее необходимо добавить MP SIEM Core в файл конфигурации(**создается автоматически**). Определить параметры:  
1. Хостнейм. **Важно!** Должен использоваться хостнейм или ip с которыми настроен компонент MP Siem Core. Узнать можно двумя способами:  
   * В адресной строке браузера на главной странице MPS Siem Core.
   * Используя "corecfg get" параметр "HostAddress"
3.  В веб интерфейсе MP SIEM Management and Configuration создать пользователя с правами администратора, или использовать стандартную УЗ Administrator
4.  Если необходима проверка CA, открыть на сервере MP SIEM Core файл *"C:\Program Files\Positive Technologies\MaxPatrol SIEM Core\.install\scripts\Certificates\rootCA.crt"* (путь может отличаться, если компонент MaxPatrol Core был установлен по другому пути) Открыть блокнотом файл rootCA.crt и скопировать его содержимое в начало или в конец файла tls-ca-bundle.pem(разместить рядом со скриптом), таким образом, чтобы строки -----END CERTIFICATE----- и -----BEGIN CERTIFICATE----- занимали целиком строку.  


```
### Создать файл конфигурации (config.json) можно командой:
mpszabbix.py -a -c (ip или hostname Core из шага 1) -u (Уз из шага 2) -ca (/usrlib/zabbix/externalscripts/tls-ca-bundle.pem или False)
###Пример1:
mpszabbix.py -a -c 1.2.3.4 -u Administrator -ca False

Пример2:
mpszabbix.py -a -c mp-siem-core.domain.local -u Administrator -ca /usrlib/zabbix/externalscripts/tls-ca-bundle.pem
```

**3.** Проверить, что файл config.json создан, прочитать лог файл, и убедиться в отсутствии ошибок:

```
### Пример файла конфигурации:
[root@zbx.proxy externalscripts]# pwd
/usr/lib/zabbix/externalscripts
[root@zbx.proxy externalscripts]# cat config.json
{
   "server1.test.local": {
      "core": "server1.test.local",
      "login": "Administrator",
      "password": "Z1FBQUFBQmV2cGN5cWYvf7Zdcdhkjkiu8UJMU0YzMXlPUE0zWEFfWERpODRzTjY3czRBSDI1TkIySlczalJmV80fdsfsd0ewefV3ZFIxLWc9Pz==",
      "cafile": "/usr/lib/zabbix/externalscripts/core-dev-ca.pem",
      "core_version": 22
   },
   "server2.test.local": {
      "core": "server2.test.local",
      "login": "Administrator",
      "password": "Z0FBQUFBQmV3U2pmVVBYOFdMajnbvdfj4lkgGI5NndoUHlrcjhPXzR0NnZ1b0VFVUw2UzalkdjfngkdfGFKDSJH32542lvLVdpYnlWV09LUnFEcEhWVlFUX1hJaEtOcnZWZ2NRb3ZCdgfs5D==",
      "cafile": false,
      "core_version": 22
   }
}
### просмотреть лог
[root@zbx.proxy externalscripts]# cat /var/log/zabbix/ptsiem_monitoring.log
```

**4.** Проверить работу скрипта:
````
### Пример 1: Запрос статусов заданий
[root@mpx-ops externalscripts]# ./mpszabbix.py -s -c server2.test.local
[{"{#JOB}": "wmi ad", "{#STATE}": 3, "{#HEALTH}": 3}, {"{#JOB}": "Solar_DNS", "{#STATE}": 2, "{#HEALTH}": 1}, {"{#JOB}": "Cisco_events", "{#STATE}": 2, "{#HEALTH}": 1}, {"{#JOB}": "24.18 eventlogs", "{#STATE}": 2, "{#HEALTH}": 1}, {"{#JOB}": "KSC_Executables", "{#STATE}": 2, "{#HEALTH}": 1}, {"{#JOB}": "cert-w7andw10", "{#STATE}": 2, "{#HEALTH}": 2}, {"{#JOB}": "kaspersky_av", "{#STATE}": 2, "{#HEALTH}": 1}, {"{#JOB}": "Win_events", "{#STATE}": 2, "{#HEALTH}": 2}, {"{#JOB}": "CERT_DC", "{#STATE}": 2, "{#HEALTH}": 1}, {"{#JOB}": "cert_additional_winlogs", "{#STATE}": 2, "{#HEALTH}": 2}, {"{#JOB}": "Solar_WindowsHosts", "{#STATE}": 2, "{#HEALTH}": 2}]

### Пример 2: Перезапуск задачи
[root@zbx.proxy externalscripts]# mpszabbix.py -r Solar_DNS -c 1.2.3.4

### Пример 3: запросить статус заданий в режиме DEBUG(объявить переменную)
[root@zbx.proxy externalscripts]# DEBUG=true ./mpszabbix.py -s -c server2.test.local
````  

**5.** [Импортировать шаблон](https://www.zabbix.com/documentation/4.0/ru/manual/xml_export_import/templates#%D0%B8%D0%BC%D0%BF%D0%BE%D1%80%D1%82) в Zabbix  

**6.** В настройках узла сети вписать ip или хостнейм, выставить переключатель "подключаться через IP|DNS" в зависимости от хостнейма MP SIEM Core, это определяет переменную {HOST.CONN}, которая передается в скрипт

**7.** [Настроить действие](https://www.zabbix.com/documentation/4.0/ru/manual/config/notifications/action/operation/remote_command) по рестарту с операцией "Выполнить удаленные команды на текущем узле сети". Команда:
````
/usr/lib/zabbix/externalscripts/mpszabbix.py -r '{ITEM.DESCRIPTION1}' -c {HOST.CONN}
````
Подробнее:  
Убедитесь, что параметр EnableRemoteCommands в конфиге заббикс сервера( или прокси) равен 1 и раскомментирован. Перезапустите демона сервера( или прокси), если изменили этот параметр.
Разместите скрипт в директории "/usr/lib/zabbix/externalscripts/"
Затем, при настройке нового действия в Настройка → Действия:  
1.  Задайте соответсвующие условия. 
2.  На вкладке Операции выберите тип операции "Удаленная команда"
3.  Выберите тип удаленной команды: пользовательский скрипт
4.  укажите каким способом этот скрипт будет выполняться (заббикс сервер или прокси)
5.  Введите удаленную команду: 
````
/usr/lib/zabbix/externalscripts/mpszabbix.py -r '{ITEM.DESCRIPTION1}' -c {HOST.CONN}
````
## Built With

* [Zabbix](https://www.zabbix.com/ru/) - Система мониторинга
* [Python](https://www.python.org/) - Язык программирования

## Versioning

Это первая версия.

## Authors

* **The_VarMaster** - *Разработка кода, тестирование* 
* **Роман Наумов** [GitHub](https://github.com/leftusername/) - *Разработка шаблона Zabbix, тестирование, разработка кода*

## License

Лицензия [LICENSE](LICENSE) позволяет использование в коммерческих организациях без цели извлечения прибыли.

