#include "str.h"
#include "common.h"

void str_trim_crlf(char *str)//去除\r\n
{
	char *p =&str[strlen(str)-1];
	while(*p=='\r'||*p=='\n')
		*p--='\0';
}

void str_split(const char *str , char *left, char *right, char c)//字符串分割,c为分割字符
{
	char *p =strchr(str,c);
	if(p==NULL)
		strcpy(left,str);
	else
	{
		strncpy(left,str,p-str);
		strcpy(right,p+1);
	}
}

int str_all_space(const char *str)//判断是否全是空白字符
{
	while(*str)
	{
		if(!isspace(*str))//isspace判断空字符
			return 0;
		str++;
	}
	return 1;
}
void str_upper(char *str)//字符串转化为大写格式
{
	while(*str)
	{
		*str =toupper(*str);//toupper:将单字符转换为大写
		str++;
	}

}
long long str_to_longlong(const char *str)//将字符串转换为long long
{
	//return atoll(str);//系统自带函数atoll,有平台不兼容
	long long result =0;
	long long mult =1;
	unsigned int len =strlen(str);
	unsigned int i;
	if(len>15)
		return 0;
	
	for(i=0;i<len;i++)
	{
		char ch =str[len-(i+1)];
		long long val;
		if(ch<'0'||ch>'9')
			return 0;
		
		val =ch - '0';
		val *=mult;
		result+=val;
		mult*=10;
	}
	return result;
}
unsigned int str_octal_to_uint(const char *str)//将字符串（八进制）转化为无符串整型
{
	unsigned int result=0;
	int seen_non_zero_digit=0;
	while(*str)
	{
		int digit =*str;
		if(!isdigit(digit)||digit>'7')//isdigit(digit)判断是否是数字
			break;
			
		if(digit!='0')
			seen_non_zero_digit=1;
		
		if(seen_non_zero_digit)
			{
				result<<=3;
				result+=(digit-'0');
			}
			str++;
	}
	return result;
}
