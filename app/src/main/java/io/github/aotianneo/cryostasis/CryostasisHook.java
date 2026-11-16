package io.github.aotianneo.cryostasis;

import android.app.Application;
import android.content.ContentResolver;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;

import java.lang.reflect.Method;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Cryostasis LSPosed entry hook.
 *
 * Intercepts MIUI/HyperOS 30-second low-battery shutdowns and transitions the device
 * into Ultra Battery Saver stasis without hardcoded obfuscated class or method names.
 */
public class CryostasisHook implements IXposedHookLoadPackage {

    private static final String TAG = "[Cryostasis] ";
    private static final String PKG_SECURITY_CENTER = "com.miui.securitycenter";
    private static final String PKG_POWER_CENTER = "com.miui.powercenter";

    private static final String ACTION_REQ_SHUT = "com.android.internal.intent.action.REQUEST_SHUTDOWN";
    private static final String ACTION_REQ_SHUT_OLD = "android.intent.action.ACTION_REQUEST_SHUTDOWN";
    private static final String EXTRA_REASON = "android.intent.extra.REASON";
    private static final String SETTING_SUPERSAVE_OPEN = "power_supersave_mode_open";

    public static volatile int sResIdWarningMsg = 0;
    public static volatile int sResIdNotifTitle = 0;
    public static volatile int sResIdNotifMsg = 0;
    public static volatile DexLocator.LocateResult sLocateResult = null;

    public static boolean claimOnce(String key) {
        try {
            return System.getProperties().putIfAbsent(key, Boolean.TRUE) == null;
        } catch (Throwable ignored) {
            return true;
        }
    }

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!PKG_SECURITY_CENTER.equals(lpparam.packageName)
                && !PKG_POWER_CENTER.equals(lpparam.packageName)) {
            return;
        }

        if (claimOnce("cryostasis.log")) {
            XposedBridge.log(TAG + "Loaded in " + lpparam.packageName + " (" + lpparam.processName + ")");
        }
        installFrameworkHooks();

        Context app = getCurrentApplication();
        if (app != null) {
            initWithContext(app, lpparam);
            return;
        }

        if (!claimOnce("cryostasis.attach")) {
            return;
        }
        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Context ctx = (Context) param.args[0];
                if (ctx != null) {
                    initWithContext(ctx, lpparam);
                }
            }
        });
    }

    public static void initWithContext(Context ctx, XC_LoadPackage.LoadPackageParam lpparam) {
        if (!claimOnce("cryostasis.init")) {
            return;
        }
        try {
            Context appCtx = ctx.getApplicationContext();
            if (appCtx != null) {
                ctx = appCtx;
            }
            resolveResourceIds(ctx);

            String sourceDir = lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null;
            String[] splitDirs = lpparam.appInfo != null ? lpparam.appInfo.splitSourceDirs : null;
            DexLocator.LocateResult res = DexLocator.locate(ctx, sourceDir, splitDirs);
            sLocateResult = res;

            applyDynamicHooks(lpparam.classLoader, res);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "initWithContext error: " + t);
        }
    }

    public static void resolveResourceIds(Context ctx) {
        try {
            Resources r = ctx.getResources();
            String pkg = ctx.getPackageName();
            sResIdWarningMsg = r.getIdentifier("power_off_warning_message", "string", pkg);
            sResIdNotifTitle = r.getIdentifier("power_off_warning_notification_title", "string", pkg);
            sResIdNotifMsg = r.getIdentifier("power_off_warning_notification_message", "plurals", pkg);
            XposedBridge.log(TAG + "Dynamic resIds: msg=" + sResIdWarningMsg
                    + ", notifTitle=" + sResIdNotifTitle + ", notifMsg=" + sResIdNotifMsg);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "resolveResourceIds error: " + t);
        }
    }

    public static void applyDynamicHooks(final ClassLoader cl, final DexLocator.LocateResult res) {
        // 1. Hook countdown start method (prevents sticky-broadcast re-trigger loop after entering stasis)
        if (res.countdownClass != null && res.countdownMethod != null) {
            try {
                Class<?> cls = XposedHelpers.findClassIfExists(res.countdownClass, cl);
                if (cls != null) {
                    XposedHelpers.findAndHookMethod(cls, res.countdownMethod, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Context ctx = extractContext(param.thisObject, res.triggerCtxField);
                            if (isSuperPowerModeOpen(ctx)) {
                                XposedBridge.log(TAG + "Already in Super Power Save mode, skip countdown UI");
                                param.setResult(null);
                            }
                        }
                    });
                    XposedBridge.log(TAG + "Hooked countdown: " + res.countdownClass + "." + res.countdownMethod + "()");
                }
            } catch (Throwable t) {
                XposedBridge.log(TAG + "Hook countdown error: " + t);
            }
        }

        // 2. Hook 30s low-battery shutdown trigger method
        if (res.triggerClass != null && res.triggerMethod != null) {
            try {
                Class<?> cls = XposedHelpers.findClassIfExists(res.triggerClass, cl);
                if (cls != null) {
                    XposedHelpers.findAndHookMethod(cls, res.triggerMethod, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + "Intercepted 30s low-battery shutdown trigger ("
                                    + res.triggerClass + "." + res.triggerMethod + ")");
                            Context ctx = extractContext(param.thisObject, res.triggerCtxField);
                            enterSuperPowerMode(ctx);
                            param.setResult(null);
                        }
                    });
                    XposedBridge.log(TAG + "Hooked trigger: " + res.triggerClass + "." + res.triggerMethod + "()");
                }
            } catch (Throwable t) {
                XposedBridge.log(TAG + "Hook trigger error: " + t);
            }
        }

        // 3. Hook REQUEST_SHUTDOWN utility methods dynamically found in DEX (skip timed bootshutdown classes)
        for (int i = 0; i < res.utilMethods.size(); i++) {
            String spec = res.utilMethods.get(i);
            String[] parts = spec.split("\\|", -1);
            if (parts.length != 3) continue;
            final String clsName = parts[0];
            final String mName = parts[1];
            final String pSig = parts[2];
            if (clsName.contains("bootshutdown") || clsName.contains("ShutdownAlarm")) {
                continue;
            }
            try {
                Class<?> cls = XposedHelpers.findClassIfExists(clsName, cl);
                if (cls == null) continue;
                Class<?>[] pTypes = DexLocator.parseParamTypes(pSig, cl);
                Object[] hookArgs = new Object[pTypes.length + 1];
                System.arraycopy(pTypes, 0, hookArgs, 0, pTypes.length);
                hookArgs[pTypes.length] = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String reason = findReasonArg(param.args);
                        if (shouldInterceptReason(reason)) {
                            XposedBridge.log(TAG + "Intercepted util " + clsName + "." + mName
                                    + " reason=" + reason);
                            Context ctx = findContextArg(param.args);
                            if (ctx == null) ctx = getCurrentApplication();
                            enterSuperPowerMode(ctx);
                            param.setResult(null);
                        }
                    }
                };
                XposedHelpers.findAndHookMethod(cls, mName, hookArgs);
                XposedBridge.log(TAG + "Hooked util: " + clsName + "." + mName + pSig);
            } catch (Throwable t) {
                XposedBridge.log(TAG + "Hook util failed " + spec + ": " + t);
            }
        }
    }

    public static void installFrameworkHooks() {
        if (!claimOnce("cryostasis.fw")) {
            return;
        }
        // Fallback Intent interception independent of any obfuscation
        XC_MethodHook intentHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args == null || param.args.length == 0) return;
                if (!(param.args[0] instanceof Intent)) return;
                Intent intent = (Intent) param.args[0];
                String action = intent.getAction();
                if (ACTION_REQ_SHUT.equals(action) || ACTION_REQ_SHUT_OLD.equals(action)) {
                    String reason = intent.getStringExtra(EXTRA_REASON);
                    if (shouldInterceptReason(reason)) {
                        XposedBridge.log(TAG + "Intercepted Framework shutdown Intent, reason=" + reason);
                        Context ctx = (param.thisObject instanceof Context)
                                ? (Context) param.thisObject
                                : getCurrentApplication();
                        enterSuperPowerMode(ctx);
                        param.setResult(null);
                    }
                }
            }
        };

        try {
            XposedHelpers.findAndHookMethod(ContextWrapper.class, "startActivity", Intent.class, intentHook);
            XposedHelpers.findAndHookMethod(ContextWrapper.class, "sendBroadcast", Intent.class, intentHook);
            Class<?> ctxImpl = XposedHelpers.findClassIfExists("android.app.ContextImpl", null);
            if (ctxImpl != null) {
                XposedHelpers.findAndHookMethod(ctxImpl, "startActivity", Intent.class, Bundle.class, intentHook);
                XposedHelpers.findAndHookMethod(ctxImpl, "sendBroadcast", Intent.class, intentHook);
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Framework intent hook error: " + t);
        }

        // Dynamic resource text replacement (dialog & notification)
        try {
            XposedHelpers.findAndHookMethod(Resources.class, "getString", int.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    int targetId = sResIdNotifTitle;
                    if (targetId == 0) return;
                    int id = (Integer) param.args[0];
                    if (id == targetId) {
                        param.setResult(isZh() ? "电量过低，即将进入超级省电" : "About to enter Ultra battery saver");
                    }
                }
            });
            XposedHelpers.findAndHookMethod(Resources.class, "getString", int.class, Object[].class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    int targetId = sResIdWarningMsg;
                    if (targetId == 0) return;
                    int id = (Integer) param.args[0];
                    if (id == targetId) {
                        Object[] fa = (Object[]) param.args[1];
                        String sec = (fa != null && fa.length > 0 && fa[0] != null) ? String.valueOf(fa[0]) : "30";
                        param.setResult(isZh()
                                ? "手机电量过低，将在" + sec + "秒内进入超级省电模式，请尽快连接充电器。"
                                : "Battery is low. Entering Ultra battery saver in " + sec + " seconds. Connect charger.");
                    }
                }
            });
            XposedHelpers.findAndHookMethod(Resources.class, "getQuantityString", int.class, int.class, Object[].class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    int targetId = sResIdNotifMsg;
                    if (targetId == 0) return;
                    int id = (Integer) param.args[0];
                    if (id == targetId) {
                        int q = (Integer) param.args[1];
                        param.setResult(isZh()
                                ? "手机电量过低，将在" + q + "秒内进入超级省电模式，请尽快连接充电器。"
                                : "Your device will enter Ultra battery saver in " + q + " seconds. Connect charger.");
                    }
                }
            });
            XposedBridge.log(TAG + "Hooked Intent & Resources");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Resources hook error: " + t);
        }
    }

    public static boolean shouldInterceptReason(String reason) {
        if (reason == null) {
            return true;
        }
        String lower = reason.toLowerCase(Locale.ROOT);
        if (lower.contains("timed_shutdown") || lower.contains("temp") || lower.contains("thermal")
                || lower.contains("userrequested") || lower.contains("reboot") || lower.contains("recovery")) {
            return false;
        }
        return lower.contains("low-battery") || lower.contains("low_battery") || lower.contains("battery");
    }

    static boolean isSuperPowerModeOpen(Context ctx) {
        if (ctx == null) return false;
        try {
            return Settings.System.getInt(ctx.getContentResolver(), SETTING_SUPERSAVE_OPEN, 0) != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    static void enterSuperPowerMode(Context ctx) {
        if (ctx == null) {
            ctx = getCurrentApplication();
        }
        if (ctx == null) {
            XposedBridge.log(TAG + "enterSuperPowerMode failed: context is null");
            return;
        }
        if (isSuperPowerModeOpen(ctx)) {
            XposedBridge.log(TAG + "Super Power Save mode already open");
            return;
        }

        // Channel 1: Stable MIUI/HyperOS PowerSaverProvider IPC
        try {
            Bundle bundle = new Bundle();
            bundle.putBoolean("POWER_SUPERSAVE_MODE_OPEN", true);
            bundle.putBoolean("POWER_SUPERSAVE_MODE_FROMUSER", true);
            ctx.getContentResolver().call(
                    Uri.parse("content://com.miui.powercenter.powersaver"),
                    "changeSuperPowerMode",
                    null,
                    bundle
            );
            XposedBridge.log(TAG + "Entered Super Power Save mode via PowerSaverProvider");
            return;
        } catch (Throwable t) {
            XposedBridge.log(TAG + "PowerSaverProvider call failed, trying fallback: " + t);
        }

        // Channel 2: Fallback to dynamically located SuperPower static helper
        DexLocator.LocateResult r = sLocateResult;
        if (r != null && r.superPowerClass != null && r.superPowerMethod != null) {
            try {
                Class<?> cls = XposedHelpers.findClassIfExists(r.superPowerClass, ctx.getClassLoader());
                if (cls != null) {
                    XposedHelpers.callStaticMethod(cls, r.superPowerMethod, ctx, true, true);
                    XposedBridge.log(TAG + "Entered Super Power Save mode via " + r.superPowerClass + "." + r.superPowerMethod);
                    return;
                }
            } catch (Throwable t) {
                XposedBridge.log(TAG + "Dynamic superPower helper fallback failed: " + t);
            }
        }

        // Channel 3: Legacy Settings fallback
        try {
            ContentResolver cr = ctx.getContentResolver();
            Settings.System.putInt(cr, SETTING_SUPERSAVE_OPEN, 1);
            XposedBridge.log(TAG + "Applied legacy Settings.System fallback");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "All SuperPower channels failed: " + t);
        }
    }

    static Context extractContext(Object instance, String fieldName) {
        if (instance != null && fieldName != null) {
            try {
                Object obj = XposedHelpers.getObjectField(instance, fieldName);
                if (obj instanceof Context) {
                    return (Context) obj;
                }
            } catch (Throwable ignored) {
            }
        }
        return getCurrentApplication();
    }

    static String findReasonArg(Object[] args) {
        if (args == null) return null;
        for (Object arg : args) {
            if (arg instanceof String) {
                return (String) arg;
            }
        }
        return null;
    }

    static Context findContextArg(Object[] args) {
        if (args == null) return null;
        for (Object arg : args) {
            if (arg instanceof Context) {
                return (Context) arg;
            }
        }
        return null;
    }

    static boolean isZh() {
        return Locale.getDefault().getLanguage().startsWith("zh");
    }

    static Context getCurrentApplication() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Method m = at.getMethod("currentApplication");
            Object app = m.invoke(null);
            if (app instanceof Application) {
                return (Application) app;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
