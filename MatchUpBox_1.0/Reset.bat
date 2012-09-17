del .\dbData\*.db /Q /F
del .\dbEP\*.* /Q /F
move .\mypem\TISPKey.pem .\TISPKey.back
del .\mypem\*.pem /Q /F
move .\TISPKey.back .\mypem\TISPKey.pem
del .\user_data\*.* /Q /F
