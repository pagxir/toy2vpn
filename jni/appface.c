#include <stdio.h>
#include <assert.h>
#include <android/log.h>
#include <jni.h>
#include <unistd.h>

#define  LOG_TAG  "TOYVPN-JNI"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

//定义目标类名称
static const char *className = "com/qifen/toyvpn/PingTunnelDevice";

static int do_loop(JNIEnv *env, jclass clazz, jint tunnel, jint udpfd, jint tunfd)
{
	pingle_do_loop(tunnel, udpfd, tunfd);
    return 0;
}

static int do_handshake(JNIEnv *env, jclass clazz, jint tunnel)
{
	pingle_do_handshake(tunnel);
    return 0;
}

static int set_dns_mode(JNIEnv *env, jclass clazz, jint tunnel)
{
	pingle_set_dnsmode(tunnel);
    return 0;
}

static jbyteArray get_configure(JNIEnv *env, jclass clazz, jint tunnel)
{
	jbyte fill[2560];
	jbyteArray result;

	int size = pingle_get_configure(tunnel, fill, sizeof(fill));

	result = (*env)->NewByteArray(env, size);
	if (result == NULL) {
		return NULL; /* out of memory error thrown */
	}

	// move from the temp structure to the java structure
	(*env)->SetByteArrayRegion(env, result, 0, size, fill);

	return result;
}

static int set_session(JNIEnv *env, jclass clazz, jstring park)
{
	const char *str;

	str = (*env)->GetStringUTFChars(env, park, 0);
	pingle_set_session(str);
	(*env)->ReleaseStringUTFChars(env, park, str);

	return 0;
}

static int set_cookies(JNIEnv *env, jclass clazz, jstring park)
{
	const char *str;

	str = (*env)->GetStringUTFChars(env, park, 0);
	pingle_set_cookies(str);
	(*env)->ReleaseStringUTFChars(env, park, str);

	return 0;
}

#include <sys/socket.h>
static int do_open_udp(JNIEnv *env, jclass clazz)
{
	int tunnel = socket(AF_INET, SOCK_DGRAM, 0);
	return tunnel;
}

static int set_secret(JNIEnv *env, jclass clazz, jstring park)
{
	const char *str;

	str = (*env)->GetStringUTFChars(env, park, 0);
	pingle_set_secret(str);
	(*env)->ReleaseStringUTFChars(env, park, str);

	return 0;
}

static int set_server(JNIEnv *env, jclass clazz, jbyteArray park, jint port)
{
	jsize  count = (*env)->GetArrayLength(env, park);  
	jbyte* data  = (jbyte*)(*env)->GetByteArrayElements(env, park, 0);  
	pingle_set_server(data, port, count);
	return 0;
}

static int do_close(JNIEnv *env, jclass clazz, jint tunnel)
{
	return close(tunnel);
}

static int do_open(JNIEnv *env, jclass clazz)
{
    return pingle_open();
}

//定义方法隐射关系
static JNINativeMethod methods[] = {
	{"do_loop", "(III)I", (void*)do_loop},
	{"do_handshake", "(I)V", (void*)do_handshake},
	{"set_dnsmode", "(I)V", (void*)set_dns_mode},
	{"get_configure", "(I)[B", (void*)get_configure},
	{"set_session", "(Ljava/lang/String;)V", (void*)set_session},
	{"set_cookies", "(Ljava/lang/String;)V", (void*)set_cookies},
	{"set_secret", "(Ljava/lang/String;)V", (void*)set_secret},
	{"set_server", "([BI)V", (void*)set_server},

	{"do_close", "(I)I", (void*)do_close},
	{"do_open_udp", "()I", (void*)do_open_udp},
	{"do_open", "()I", (void*)do_open},
};

jint JNI_OnLoad(JavaVM* vm, void* reserved){
	//声明变量
	jclass clazz;
	JNIEnv* env = NULL;
	jint result = JNI_ERR;
	int methodsLenght;

	//获取JNI环境对象
	if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK) {
		LOGE("ERROR: GetEnv failed\n");
		return JNI_ERR;
	}
	assert(env != NULL);

	//注册本地方法.Load 目标类
	clazz = (*env)->FindClass(env, className);
	if (clazz == NULL) {
		LOGE("Native registration unable to find class '%s'", className);
		return JNI_ERR;
	}

	//建立方法隐射关系
	//取得方法长度
	methodsLenght = sizeof(methods) / sizeof(methods[0]);
	if ((*env)->RegisterNatives(env, clazz, methods, methodsLenght) < 0) {
		LOGE("RegisterNatives failed for '%s'", className);
		return JNI_ERR;
	}
	//
	result = JNI_VERSION_1_4;
	return result;
}

//onUnLoad方法，在JNI组件被释放时调用
void JNI_OnUnload(JavaVM* vm, void* reserved){
	LOGE("call JNI_OnUnload ~~!!");
}

