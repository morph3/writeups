# Click Me!

Mobile, Hard, 466 Points


![](https://i.imgur.com/gPBTzKa.png)

We can see the following code blocks in the application.

```java
  public final void cookieViewClick(View paramView) {
    int i = this.CLICKS + 1;
    this.CLICKS = i;
    if (i >= 13371337)
      this.CLICKS = 13371337; 
    ((TextView)findViewById(2131230837)).setText(String.valueOf(this.CLICKS));
  }
```


```java
  public final native String getFlag();
  
  public final void getFlagButtonClick(View paramView) {
    Intrinsics.checkNotNullParameter(paramView, "view");
    if (this.CLICKS == 99999999) {
      String str = getFlag();
      Toast.makeText(getApplicationContext(), str, 0).show();
    } else {
      Toast.makeText(getApplicationContext(), "You do not have enough cookies to get the flag", 0).show();
    } 
  }
```


We can debug it with frida

x.js,
```js
console.log("Enumerating methods of MainActivity");
Java.perform(function() {
  const groups = Java.enumerateMethods('*MainActivity*!*');
  console.log(JSON.stringify(groups, null, 2));
});
```

`frida -U -l x.js  2900`


```
Enumerating methods of MainActivity
[
  {
    "loader": "<instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>",
    "classes": [
      {
        "name": "com.example.clickme.MainActivity$Companion",
        "methods": [
          "$init"
        ]
      },
      {
        "name": "com.example.clickme.MainActivity",
        "methods": [
          "$init",
          "cookieViewClick",
          "getFlag",
          "getFlagButtonClick",
          "onCreate"
        ]
      }
    ]
  }
]
```



Solver frida script,

```js
console.log("Hello");
Java.perform(function() {
    var MainActivity = Java.use("com.example.clickme.MainActivity");
    var cookieViewClick = MainActivity.cookieViewClick;
    cookieViewClick.implementation = function (v) {
      // Show a message to know that the function got called
      send('cookieViewClick');

      // Call the original onClick handler
      cookieViewClick.call(this, v);

      // Set our values after running the original onClick handler
      this.CLICKS.value = 99999999;

      // Log to the console that it's done, and we should have the flag!
      console.log('Done:' + JSON.stringify(this.CLICKS));
    };



})
```

![](https://i.imgur.com/dyuJp4u.png)



Flag `flag{849d9e5421c59358ee4d568adebc5a70}`
