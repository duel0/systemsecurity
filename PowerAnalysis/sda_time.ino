const char *in_memory_pwd = "104236";
const int pwd_len = 6;
const int led_pin = 13;

char buf[33];

int check(const char *str1, const char* str2){
  int i=0;
  while(i < pwd_len && str1[i] == str2[i]) i++;
  return i; 
}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  pinMode(led_pin,OUTPUT);
  digitalWrite(led_pin,LOW);
}

  

void loop() {
  // put your main code here, to run repeatedly:
  int r;
  
  Serial.setTimeout(10);
  while(!Serial.available())
  delay(1000);
  r = Serial.readBytes(buf,33);
  buf[r]='\0';
  digitalWrite(led_pin,HIGH);
  int permission = (6 == check(buf, in_memory_pwd));
  digitalWrite(led_pin,LOW);
  if (permission){
    Serial.println("Good Password");
  }
  else
    Serial.print("Wrong Password");
}
