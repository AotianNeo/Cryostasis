package io.github.aotianneo.cryostasis;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runtime DEX bytecode anchor locator that resolves obfuscated MIUI/HyperOS SecurityCenter
 * classes and methods across all app versions using invariant string anchors and caches
 * resolved targets per host package version.
 */
public class DexLocator {

    public static final String ANCHOR_LOW_BAT = "charger,low-battery";
    public static final String ANCHOR_REQ_SHUT = "com.android.internal.intent.action.REQUEST_SHUTDOWN";
    public static final String ANCHOR_REQ_SHUT_OLD = "android.intent.action.ACTION_REQUEST_SHUTDOWN";
    public static final String ANCHOR_COUNTDOWN = "Already displayed power off countdown";
    public static final String ANCHOR_CHANGE_SP = "changeSuperPowerMode";
    public static final String ANCHOR_SP_OPEN = "POWER_SUPERSAVE_MODE_OPEN";

    private static final String PREF_NAME = "cryostasis_dex_locator_v1";

    public static class LocateResult {
        public String triggerClass;
        public String triggerMethod;
        public String triggerCtxField;

        public String countdownClass;
        public String countdownMethod;

        public List<String> utilMethods = new ArrayList<>(); // format: className|methodName|paramSig

        public String superPowerClass;
        public String superPowerMethod;
    }

    public static LocateResult locate(Context context, String apkPath, String[] splitPaths) {
        String cacheKey = buildCacheKey(context, apkPath);
        if (context != null && cacheKey != null) {
            LocateResult cached = loadCache(context, cacheKey);
            if (cached != null) {
                return cached;
            }
        }

        LocateResult result = new LocateResult();
        scanApk(apkPath, result);
        if (splitPaths != null) {
            for (String sp : splitPaths) {
                if (sp != null) {
                    scanApk(sp, result);
                }
            }
        }

        if (context != null && cacheKey != null && hasAnyHit(result)) {
            saveCache(context, cacheKey, result);
        }
        return result;
    }

    private static boolean hasAnyHit(LocateResult r) {
        return r.triggerClass != null || r.countdownClass != null || !r.utilMethods.isEmpty();
    }

    private static String buildCacheKey(Context context, String apkPath) {
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            long vc = Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode;
            return vc + "_" + pi.lastUpdateTime + "_" + apkPath;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static LocateResult loadCache(Context context, String key) {
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            if (!key.equals(sp.getString("key", null))) {
                return null;
            }
            LocateResult r = new LocateResult();
            r.triggerClass = sp.getString("tc", null);
            r.triggerMethod = sp.getString("tm", null);
            r.triggerCtxField = sp.getString("tf", null);
            r.countdownClass = sp.getString("cc", null);
            r.countdownMethod = sp.getString("cm", null);
            r.superPowerClass = sp.getString("sc", null);
            r.superPowerMethod = sp.getString("sm", null);
            String utils = sp.getString("um", "");
            if (utils != null && !utils.isEmpty()) {
                for (String item : utils.split("\n")) {
                    if (!item.isEmpty()) {
                        r.utilMethods.add(item);
                    }
                }
            }
            return r;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void saveCache(Context context, String key, LocateResult r) {
        try {
            SharedPreferences sp = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            SharedPreferences.Editor ed = sp.edit();
            ed.putString("key", key);
            ed.putString("tc", r.triggerClass);
            ed.putString("tm", r.triggerMethod);
            ed.putString("tf", r.triggerCtxField);
            ed.putString("cc", r.countdownClass);
            ed.putString("cm", r.countdownMethod);
            ed.putString("sc", r.superPowerClass);
            ed.putString("sm", r.superPowerMethod);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < r.utilMethods.size(); i++) {
                if (i > 0) sb.append('\n');
                sb.append(r.utilMethods.get(i));
            }
            ed.putString("um", sb.toString());
            ed.apply();
        } catch (Throwable ignored) {
        }
    }

    public static void scanApk(String apkPath, LocateResult out) {
        if (apkPath == null) return;
        try (ZipFile zip = new ZipFile(apkPath)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (name.startsWith("classes") && name.endsWith(".dex") && !name.contains("/")) {
                    byte[] dex = readEntry(zip.getInputStream(e), (int) e.getSize());
                    scanDex(dex, out);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static byte[] readEntry(InputStream is, int sizeHint) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(sizeHint > 0 ? sizeHint : 65536);
        byte[] buf = new byte[16384];
        int n;
        while ((n = is.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    public static void scanDex(byte[] dex, LocateResult out) {
        if (dex == null || dex.length < 0x70) return;
        int strIdsSize = u32(dex, 56);
        int strIdsOff = u32(dex, 60);
        int typeIdsSize = u32(dex, 64);
        int typeIdsOff = u32(dex, 68);
        int protoIdsSize = u32(dex, 72);
        int protoIdsOff = u32(dex, 76);
        int fieldIdsSize = u32(dex, 80);
        int fieldIdsOff = u32(dex, 84);
        int methodIdsSize = u32(dex, 88);
        int methodIdsOff = u32(dex, 92);
        int classDefsSize = u32(dex, 96);
        int classDefsOff = u32(dex, 100);

        int idxLowBat = findStringIndex(dex, strIdsSize, strIdsOff, ANCHOR_LOW_BAT);
        int idxReqShut = findStringIndex(dex, strIdsSize, strIdsOff, ANCHOR_REQ_SHUT);
        int idxReqShutOld = findStringIndex(dex, strIdsSize, strIdsOff, ANCHOR_REQ_SHUT_OLD);
        int idxCountdown = findStringIndex(dex, strIdsSize, strIdsOff, ANCHOR_COUNTDOWN);
        int idxChangeSp = findStringIndex(dex, strIdsSize, strIdsOff, ANCHOR_CHANGE_SP);
        int idxSpOpen = findStringIndex(dex, strIdsSize, strIdsOff, ANCHOR_SP_OPEN);

        if (idxLowBat < 0 && idxReqShut < 0 && idxReqShutOld < 0 && idxCountdown < 0 && idxChangeSp < 0) {
            return;
        }

        int ctxTypeIdx = findTypeIndex(dex, typeIdsSize, typeIdsOff, strIdsSize, strIdsOff, "Landroid/content/Context;");

        int[] pos = new int[1];
        for (int ci = 0; ci < classDefsSize; ci++) {
            int cBase = classDefsOff + ci * 32;
            int classDataOff = u32(dex, cBase + 24);
            if (classDataOff == 0) continue;

            pos[0] = classDataOff;
            int sfCnt = readUleb(dex, pos);
            int ifCnt = readUleb(dex, pos);
            int dmCnt = readUleb(dex, pos);
            int vmCnt = readUleb(dex, pos);

            // Skip static fields
            for (int i = 0; i < sfCnt; i++) {
                readUleb(dex, pos);
                readUleb(dex, pos);
            }
            // Scan instance fields for Context field
            String firstCtxField = null;
            int fIdx = 0;
            for (int i = 0; i < ifCnt; i++) {
                fIdx += readUleb(dex, pos);
                readUleb(dex, pos);
                if (firstCtxField == null && ctxTypeIdx >= 0 && fIdx < fieldIdsSize) {
                    int fTypeIdx = u16(dex, fieldIdsOff + fIdx * 8 + 2);
                    if (fTypeIdx == ctxTypeIdx) {
                        int fNameStrIdx = u32(dex, fieldIdsOff + fIdx * 8 + 4);
                        firstCtxField = getString(dex, strIdsOff, fNameStrIdx);
                    }
                }
            }

            // Scan direct & virtual methods
            for (int listKind = 0; listKind < 2; listKind++) {
                int mCnt = listKind == 0 ? dmCnt : vmCnt;
                int mIdx = 0;
                for (int i = 0; i < mCnt; i++) {
                    mIdx += readUleb(dex, pos);
                    readUleb(dex, pos); // access_flags
                    int codeOff = readUleb(dex, pos);
                    if (codeOff == 0 || mIdx >= methodIdsSize) continue;

                    int insnsSize = u32(dex, codeOff + 12);
                    int insnsOff = codeOff + 16;
                    int flags = scanMethodStrings(dex, insnsOff, insnsSize,
                            idxLowBat, idxReqShut, idxReqShutOld, idxCountdown, idxChangeSp, idxSpOpen);
                    if (flags == 0) continue;

                    int mBase = methodIdsOff + mIdx * 8;
                    int mClsTypeIdx = u16(dex, mBase);
                    int mProtoIdx = u16(dex, mBase + 2);
                    int mNameStrIdx = u32(dex, mBase + 4);

                    String clsDesc = getType(dex, typeIdsOff, strIdsOff, mClsTypeIdx);
                    String clsName = descriptorToJavaName(clsDesc);
                    String mName = getString(dex, strIdsOff, mNameStrIdx);
                    String paramSig = getProtoParamsSig(dex, protoIdsOff, typeIdsOff, strIdsOff, mProtoIdx);
                    String retType = getProtoRet(dex, protoIdsOff, typeIdsOff, strIdsOff, mProtoIdx);

                    if ((flags & 1) != 0 && "()".equals(paramSig) && "V".equals(retType)) {
                        out.triggerClass = clsName;
                        out.triggerMethod = mName;
                        out.triggerCtxField = firstCtxField;
                    }
                    if ((flags & 8) != 0 && "()".equals(paramSig) && "V".equals(retType)) {
                        out.countdownClass = clsName;
                        out.countdownMethod = mName;
                    }
                    if ((flags & (2 | 4)) != 0 && "V".equals(retType)) {
                        String entry = clsName + "|" + mName + "|" + paramSig;
                        if (!out.utilMethods.contains(entry)) {
                            out.utilMethods.add(entry);
                        }
                    }
                    if ((flags & 16) != 0 && (flags & 32) != 0
                            && "(Landroid/content/Context;ZZ)".equals(paramSig) && "V".equals(retType)) {
                        out.superPowerClass = clsName;
                        out.superPowerMethod = mName;
                    }
                }
            }
        }
    }

    private static int scanMethodStrings(byte[] dex, int insnsOff, int insnsSize,
            int s1, int s2, int s3, int s4, int s5, int s6) {
        int flags = 0;
        int ip = 0;
        while (ip < insnsSize) {
            int w0 = u16(dex, insnsOff + ip * 2);
            int op = w0 & 0xFF;
            if (op == 0x1A && ip + 1 < insnsSize) {
                int sidx = u16(dex, insnsOff + (ip + 1) * 2);
                flags |= matchStr(sidx, s1, s2, s3, s4, s5, s6);
                ip += 2;
            } else if (op == 0x1B && ip + 2 < insnsSize) {
                int sidx = u32(dex, insnsOff + (ip + 1) * 2);
                flags |= matchStr(sidx, s1, s2, s3, s4, s5, s6);
                ip += 3;
            } else {
                ip += insnStep(dex, insnsOff, ip, w0, op);
            }
        }
        return flags;
    }

    private static int matchStr(int sidx, int s1, int s2, int s3, int s4, int s5, int s6) {
        int f = 0;
        if (sidx == s1) f |= 1;
        if (sidx == s2) f |= 2;
        if (sidx == s3) f |= 4;
        if (sidx == s4) f |= 8;
        if (sidx == s5) f |= 16;
        if (sidx == s6) f |= 32;
        return f;
    }

    private static int insnStep(byte[] dex, int insnsOff, int ip, int w0, int op) {
        if (op == 0x00) {
            if (w0 == 0x0100) {
                int sz = u16(dex, insnsOff + (ip + 1) * 2);
                return 4 + sz * 2;
            } else if (w0 == 0x0200) {
                int sz = u16(dex, insnsOff + (ip + 1) * 2);
                return 2 + sz * 4;
            } else if (w0 == 0x0300) {
                int ew = u16(dex, insnsOff + (ip + 1) * 2);
                int es = u32(dex, insnsOff + (ip + 2) * 2);
                return 4 + (es * ew + 1) / 2;
            }
            return 1;
        }
        if ((op <= 0x12 && (op == 0x01 || op == 0x04 || op == 0x07 || op >= 0x0A))
                || op == 0x1D || op == 0x1E || op == 0x21 || op == 0x27 || op == 0x28
                || (op >= 0x7B && op <= 0x8F) || (op >= 0xB0 && op <= 0xCF)) {
            return 1;
        }
        if (op == 0x02 || op == 0x05 || op == 0x08 || op == 0x13 || op == 0x15 || op == 0x16
                || op == 0x19 || op == 0x1C || op == 0x1F || op == 0x20 || op == 0x22
                || op == 0x23 || op == 0x29 || (op >= 0x2D && op <= 0x6D)
                || (op >= 0x90 && op <= 0xAF) || (op >= 0xD0 && op <= 0xE2)) {
            return 2;
        }
        if (op == 0x03 || op == 0x06 || op == 0x09 || op == 0x14 || op == 0x17
                || op == 0x24 || op == 0x25 || op == 0x26 || op == 0x2A || op == 0x2B || op == 0x2C
                || (op >= 0x6E && op <= 0x78)) {
            return 3;
        }
        if (op == 0x18) {
            return 5;
        }
        return 1;
    }

    private static int findStringIndex(byte[] dex, int size, int off, String target) {
        int lo = 0, hi = size - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            String s = getString(dex, off, mid);
            int cmp = compareMutf8(s, target);
            if (cmp == 0) return mid;
            if (cmp < 0) lo = mid + 1;
            else hi = mid - 1;
        }
        return -1;
    }

    private static int compareMutf8(String a, String b) {
        byte[] ba = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        int len = Math.min(ba.length, bb.length);
        for (int i = 0; i < len; i++) {
            int va = ba[i] & 0xFF;
            int vb = bb[i] & 0xFF;
            if (va != vb) return va - vb;
        }
        return ba.length - bb.length;
    }

    private static int findTypeIndex(byte[] dex, int typeSize, int typeOff, int strSize, int strOff, String desc) {
        int sIdx = findStringIndex(dex, strSize, strOff, desc);
        if (sIdx < 0) return -1;
        int lo = 0, hi = typeSize - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int v = u32(dex, typeOff + mid * 4);
            if (v == sIdx) return mid;
            if (v < sIdx) lo = mid + 1;
            else hi = mid - 1;
        }
        return -1;
    }

    private static String getString(byte[] dex, int strIdsOff, int idx) {
        int dataOff = u32(dex, strIdsOff + idx * 4);
        int[] p = new int[]{dataOff};
        readUleb(dex, p);
        int start = p[0];
        int end = start;
        while (end < dex.length && dex[end] != 0) end++;
        return new String(dex, start, end - start, StandardCharsets.UTF_8);
    }

    private static String getType(byte[] dex, int typeIdsOff, int strIdsOff, int typeIdx) {
        int sIdx = u32(dex, typeIdsOff + typeIdx * 4);
        return getString(dex, strIdsOff, sIdx);
    }

    private static String getProtoRet(byte[] dex, int protoOff, int typeOff, int strOff, int protoIdx) {
        int retTypeIdx = u32(dex, protoOff + protoIdx * 12 + 4);
        return getType(dex, typeOff, strOff, retTypeIdx);
    }

    private static String getProtoParamsSig(byte[] dex, int protoOff, int typeOff, int strOff, int protoIdx) {
        int paramsOff = u32(dex, protoOff + protoIdx * 12 + 8);
        if (paramsOff == 0) return "()";
        int len = u32(dex, paramsOff);
        StringBuilder sb = new StringBuilder("(");
        for (int i = 0; i < len; i++) {
            int tIdx = u16(dex, paramsOff + 4 + i * 2);
            sb.append(getType(dex, typeOff, strOff, tIdx));
        }
        sb.append(')');
        return sb.toString();
    }

    public static String descriptorToJavaName(String desc) {
        if (desc == null || desc.length() < 2) return desc;
        if (desc.charAt(0) == 'L' && desc.charAt(desc.length() - 1) == ';') {
            return desc.substring(1, desc.length() - 1).replace('/', '.');
        }
        return desc;
    }

    public static Class<?>[] parseParamTypes(String paramSig, ClassLoader cl) throws ClassNotFoundException {
        if (paramSig == null || paramSig.length() <= 2) return new Class<?>[0];
        List<Class<?>> list = new ArrayList<>();
        int i = 1;
        int end = paramSig.length() - 1;
        while (i < end) {
            char c = paramSig.charAt(i);
            if (c == 'Z') { list.add(boolean.class); i++; }
            else if (c == 'B') { list.add(byte.class); i++; }
            else if (c == 'C') { list.add(char.class); i++; }
            else if (c == 'S') { list.add(short.class); i++; }
            else if (c == 'I') { list.add(int.class); i++; }
            else if (c == 'J') { list.add(long.class); i++; }
            else if (c == 'F') { list.add(float.class); i++; }
            else if (c == 'D') { list.add(double.class); i++; }
            else if (c == 'L') {
                int semi = paramSig.indexOf(';', i);
                String name = paramSig.substring(i + 1, semi).replace('/', '.');
                list.add(Class.forName(name, false, cl));
                i = semi + 1;
            } else if (c == '[') {
                int start = i;
                while (paramSig.charAt(i) == '[') i++;
                if (paramSig.charAt(i) == 'L') {
                    int semi = paramSig.indexOf(';', i);
                    i = semi + 1;
                } else {
                    i++;
                }
                String arrName = paramSig.substring(start, i).replace('/', '.');
                list.add(Class.forName(arrName, false, cl));
            } else {
                i++;
            }
        }
        return list.toArray(new Class<?>[0]);
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static int readUleb(byte[] b, int[] pos) {
        int res = 0, shift = 0, p = pos[0];
        while (true) {
            int v = b[p++] & 0xFF;
            res |= (v & 0x7F) << shift;
            if ((v & 0x80) == 0) break;
            shift += 7;
        }
        pos[0] = p;
        return res;
    }

    // CLI entry for device-side ART verification via dalvikvm
    public static void main(String[] args) {
        if (args.length == 0) return;
        long t0 = System.currentTimeMillis();
        LocateResult r = new LocateResult();
        scanApk(args[0], r);
        long dt = System.currentTimeMillis() - t0;
        System.out.println("elapsed_ms=" + dt);
        System.out.println("trigger=" + r.triggerClass + "." + r.triggerMethod + " ctxField=" + r.triggerCtxField);
        System.out.println("countdown=" + r.countdownClass + "." + r.countdownMethod);
        System.out.println("superPower=" + r.superPowerClass + "." + r.superPowerMethod);
        System.out.println("utils=" + r.utilMethods);
    }
}
