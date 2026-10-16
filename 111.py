import requests


headers = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
    "Origin": "https://www.fangdi.com.cn",
    "Pragma": "no-cache",
    "Referer": "https://www.fangdi.com.cn/old_house/old_house_list.html?district=53c7b05ea45cf006&area=6ca9fe5a544e3555&verifyNo=&region=01cb7d8e75a71723&blockName=&check_input=yv9s&time=6ca9fe5a544e3555&location=",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0",
    "X-Requested-With": "XMLHttpRequest",
    "sec-ch-ua": "\"Microsoft Edge\";v=\"155\", \"Chromium\";v=\"155\", \"Not(A:Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"macOS\""
}
cookies = {
    "JSESSIONID": "AF753DD69A33660AA4F5D2FE6AE524FB",
    "UA1L1zGonajvO": "60RZuTNtCBRefMF2ijn606K6TYWfCAhoxm3VinN3rslHJx2E2JK1knmEw5to5uOty4PB6JgJzD_AfHYC9OsOmBCA",
    "e5c777bf-df51-4240-90a0-c7ba04a4b424": "WyIyNzg4MjU0NDcxIl0",
    "UA1L1zGonajvP": "0zjfqEaVN4gLaQAoORUaYE78IO8g2rP8UHqnclJLqqrQIS4uxntzf9QTaXp8T08GLbip49XVHdt2ennAstd_DdVQxJ0lNGPdZknb8i2cGX9CGT3tDFRhZ8t_Nu_ci4ME_fr8xoTwxwu0.MNQM4UHs0.GjTg7Dp0NJCy5YC4FwB43XhaHiPskm7gTgv2kGvleFc0freREBN6Tjn7UgFqGjX1A6dsNDgNyRkqLq4GrB_YsqipCrVmpu6Q3OusdRYFV8jYqhARD1IuogkT5A2uvT.lwBe.u6YKG9ZLJn4uHOvMEfL2Dfh3eQNVF5ziue4mU3xxSGfreZgz571jsUV0zJcpTY_nvoK290R6SpQl6lv0sWgbuRrC5aQYQSfMJGaU6i4eWlFyYFzcXorie8RO1S5zkSS784k_rd1kCYecnVbrlY3zZ7niKxw71vYows3b7_"
}
url = 'https://www.fangdi.com.cn/oldhouse/selectOldHouse.action'
params = {
    "XJlCTRRM": "08X60qAlqWDWyyzArKmufMlV6IRuvhgMde4HcZE7bmfPul8r7hTUfp97jynlEfEOKXiuxfmtnrccW9Ma6yR7t5gBSJwycXjnODOGVY_yomsumYqy_7xhgAG"
}
data = 'district=53c7b05ea45cf006&area=6ca9fe5a544e3555&location=&price=undefined&region=01cb7d8e75a71723&blockName=&time=6ca9fe5a544e3555&houseType=undefined&listingNo=undefined&verifyNo=&currentPage=1'
response = requests.post(url, headers=headers, cookies=cookies, params=params, data=data)
response.close()
print(response.text)
print(response)