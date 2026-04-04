package com.shell.protector;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Android 二进制清单 (AXML) 编辑器。
 * <p>
 * 解析 AndroidManifest.xml 的二进制格式，将 &lt;application android:name="..."&gt;
 * 替换为壳入口 ProxyApplication，并记录原始 Application 类名。
 */
public class ManifestEditor {

    // ── AXML Chunk 类型常量 ─────────────────────────────────────
    private static final int CHUNK_AXML_FILE       = 0x00080003;
    private static final int CHUNK_STRING_POOL     = 0x001C0001;
    private static final int CHUNK_RESOURCE_IDS    = 0x00080180;
    private static final int CHUNK_START_NAMESPACE  = 0x00100100;
    private static final int CHUNK_END_NAMESPACE    = 0x00100101;
    private static final int CHUNK_START_TAG        = 0x00100102;
    private static final int CHUNK_END_TAG          = 0x00100103;
    private static final int CHUNK_TEXT             = 0x00100104;

    private static final int ATTR_TYPE_STRING = 0x03;
    private static final int ATTRIBUTE_BYTE_SIZE = 20; // 5 × int32

    private static final String PROXY_APPLICATION = "com.shell.stub.ProxyApplication";
    private static final String TAG_APPLICATION   = "application";
    private static final String ATTR_NAME         = "name";
    // android:name 对应的资源 ID
    private static final int RES_ANDROID_NAME = 0x01010003;
    // android:appComponentFactory 对应的资源 ID
    private static final int RES_APP_COMPONENT_FACTORY = 0x0101057A;

    // ── 编辑结果 ────────────────────────────────────────────────

    public static class EditResult {
        private final byte[] modifiedManifest;
        private final String originalApplicationName;

        public EditResult(byte[] modifiedManifest, String originalApplicationName) {
            this.modifiedManifest = modifiedManifest;
            this.originalApplicationName = originalApplicationName;
        }

        public byte[] getModifiedManifest() {
            return modifiedManifest;
        }

        public String getOriginalApplicationName() {
            return originalApplicationName;
        }
    }

    // ── 主入口 ──────────────────────────────────────────────────

    /**
     * 处理二进制 AndroidManifest.xml，替换 application 类名。
     *
     * @param raw 原始二进制清单
     * @return 编辑结果，包含修改后的字节与原始 Application 类名
     */
    public EditResult process(byte[] raw) throws IOException {
        ByteBuffer buf = wrap(raw);

        // ① 验证 AXML 头
        int magic = buf.getInt();
        if (magic != CHUNK_AXML_FILE) {
            throw new IOException("非法 AXML 魔数: 0x" + Integer.toHexString(magic));
        }
        int fileSize = buf.getInt();

        // ② 解析 StringPool
        int spStart = buf.position();
        int spType = buf.getInt();
        if (spType != CHUNK_STRING_POOL) {
            throw new IOException("预期 StringPool chunk，实际: 0x" + Integer.toHexString(spType));
        }
        int spChunkSize   = buf.getInt();
        int stringCount   = buf.getInt();
        int styleCount    = buf.getInt();
        int flags         = buf.getInt();
        boolean isUtf8    = (flags & (1 << 8)) != 0;
        int stringsOffset = buf.getInt(); // 相对于 chunk 起始
        int stylesOffset  = buf.getInt(); // 相对于 chunk 起始，0 表示无 style

        int[] stringOffsets = readIntArray(buf, stringCount);
        int[] styleOffsets  = readIntArray(buf, styleCount);

        // 解析所有字符串
        List<String> strings = new ArrayList<>(stringCount);
        for (int i = 0; i < stringCount; i++) {
            buf.position(spStart + stringsOffset + stringOffsets[i]);
            strings.add(isUtf8 ? decodeUtf8(buf) : decodeUtf16(buf));
        }

        // 保存 style 原始数据（若存在）
        byte[] rawStyleData = null;
        if (styleCount > 0 && stylesOffset != 0) {
            int absStyleStart = spStart + stylesOffset;
            int absStyleEnd   = spStart + spChunkSize;
            rawStyleData = new byte[absStyleEnd - absStyleStart];
            System.arraycopy(raw, absStyleStart, rawStyleData, 0, rawStyleData.length);
        }

        // 保存 StringPool 之后的全部数据（ResourceIDs + XML 树）
        int afterSp = spStart + spChunkSize;
        byte[] tail = new byte[raw.length - afterSp];
        System.arraycopy(raw, afterSp, tail, 0, tail.length);

        // ③ 解析 ResourceID 表，用于精确匹配 android:name
        int[] resourceIds = parseResourceIds(tail);

        // ④ 定位 <application> 标签中的 android:name 属性
        int applicationIdx = indexOfString(strings, TAG_APPLICATION);
        if (applicationIdx == -1) {
            throw new IOException("StringPool 中未找到 'application' 字符串");
        }

        int nameAttrIdx = resolveNameAttrIndex(strings, resourceIds);

        // 扫描 XML 树
        LocateResult loc = locateAppNameAttribute(tail, applicationIdx, nameAttrIdx, strings.size());

        String originalAppName;
        if (loc != null) {
            originalAppName = strings.get(loc.stringIndex);
            strings.set(loc.stringIndex, PROXY_APPLICATION);
            System.out.printf("[ManifestEditor] 原始 Application: %s -> %s%n",
                    originalAppName, PROXY_APPLICATION);
        } else {
            originalAppName = "";
            int proxyStringIdx = strings.size();
            strings.add(PROXY_APPLICATION);

            int androidNsIdx = indexOfString(strings,
                    "http://schemas.android.com/apk/res/android");
            if (androidNsIdx == -1) {
                throw new IOException("StringPool 中未找到 Android 命名空间 URI");
            }

            tail = injectNameAttribute(tail, applicationIdx, nameAttrIdx,
                    proxyStringIdx, androidNsIdx, resourceIds);
            System.out.printf("[ManifestEditor] <application> 未声明 android:name，"
                    + "已注入 android:name=\"%s\"%n", PROXY_APPLICATION);
        }

        // ④-b 移除 appComponentFactory 属性，避免 MIUI 等 ROM
        //      因找不到 CoreComponentFactory 而跳过 ProxyApplication
        int appCompFactoryIdx = resolveResIdIndex(resourceIds, RES_APP_COMPONENT_FACTORY);
        if (appCompFactoryIdx >= 0) {
            tail = removeAttribute(tail, applicationIdx, appCompFactoryIdx);
        }

        // ⑤ 重建 StringPool
        byte[] newStringPool = rebuildStringPool(strings, isUtf8, flags, styleCount,
                styleOffsets, rawStyleData);

        // ⑥ 组装最终文件
        int newFileSize = 8 + newStringPool.length + tail.length;
        byte[] result = new byte[newFileSize];
        ByteBuffer out = wrap(result);
        out.putInt(CHUNK_AXML_FILE);
        out.putInt(newFileSize);
        out.put(newStringPool);
        out.put(tail);

        return new EditResult(result, originalAppName);
    }

    // ── 属性定位 ────────────────────────────────────────────────

    private static class LocateResult {
        final int stringIndex;

        LocateResult(int stringIndex) {
            this.stringIndex = stringIndex;
        }
    }

    /**
     * 在 XML 树字节流中找到 &lt;application&gt; 的 android:name 属性，返回其值的字符串索引。
     */
    private LocateResult locateAppNameAttribute(byte[] xmlTree, int applicationIdx,
                                                 int nameAttrIdx, int stringCount) {
        ByteBuffer buf = wrap(xmlTree);
        while (buf.remaining() >= 8) {
            int chunkPos  = buf.position();
            int chunkType = buf.getInt();
            int chunkSize = buf.getInt();
            if (chunkSize < 8 || chunkPos + chunkSize > xmlTree.length) break;

            if (chunkType == CHUNK_START_TAG) {
                buf.getInt(); // lineNumber
                buf.getInt(); // comment
                buf.getInt(); // namespaceUri
                int tagName  = buf.getInt();
                buf.getShort(); // attributeStart
                buf.getShort(); // attributeSize
                int attrCount = buf.getShort() & 0xFFFF;
                buf.getShort(); // idIndex
                buf.getShort(); // classIndex
                buf.getShort(); // styleIndex

                if (tagName == applicationIdx) {
                    for (int i = 0; i < attrCount; i++) {
                        buf.getInt(); // namespace
                        int aName     = buf.getInt();
                        int aRawValue = buf.getInt();
                        buf.getShort(); // valueSize
                        buf.get();      // res0
                        int aType     = buf.get() & 0xFF;
                        int aData     = buf.getInt();

                        if (aName == nameAttrIdx) {
                            int targetIdx = (aType == ATTR_TYPE_STRING) ? aData : aRawValue;
                            if (targetIdx >= 0 && targetIdx < stringCount) {
                                return new LocateResult(targetIdx);
                            }
                        }
                    }
                    return null;
                }
            }

            buf.position(chunkPos + chunkSize);
        }
        return null;
    }

    // ── 属性注入 ──────────────────────────────────────────────────

    /**
     * 向 &lt;application&gt; 标签注入 android:name 属性（用于原始清单未声明该属性的场景）。
     * 属性必须按 resource ID 升序插入，否则 Android 的 obtainStyledAttributes
     * 二分查找会找不到该属性。
     */
    private byte[] injectNameAttribute(byte[] xmlTree, int applicationIdx,
                                        int nameAttrIdx, int proxyStringIdx,
                                        int androidNsIdx, int[] resourceIds) {
        ByteBuffer buf = wrap(xmlTree);

        while (buf.remaining() >= 8) {
            int chunkPos  = buf.position();
            int chunkType = buf.getInt();
            int chunkSize = buf.getInt();
            if (chunkSize < 8 || chunkPos + chunkSize > xmlTree.length) break;

            if (chunkType == CHUNK_START_TAG) {
                buf.getInt(); // lineNumber
                buf.getInt(); // comment
                buf.getInt(); // namespaceUri
                int tagName = buf.getInt();

                if (tagName == applicationIdx) {
                    buf.getShort(); // attributeStart
                    buf.getShort(); // attributeSize
                    int attrCountPos = buf.position();
                    int attrCount = buf.getShort() & 0xFFFF;
                    buf.getShort(); // idIndex
                    buf.getShort(); // classIndex
                    buf.getShort(); // styleIndex

                    int attrsStart = buf.position();

                    // Find sorted insertion point by resource ID
                    int insertIdx = attrCount;
                    for (int i = 0; i < attrCount; i++) {
                        int attrOff = attrsStart + i * ATTRIBUTE_BYTE_SIZE;
                        int nameIdx = getIntAt(xmlTree, attrOff + 4);
                        int resId = (nameIdx >= 0 && nameIdx < resourceIds.length)
                                ? resourceIds[nameIdx] : 0xFFFFFFFF;
                        if (resId > RES_ANDROID_NAME) {
                            insertIdx = i;
                            break;
                        }
                    }

                    int insertPos = attrsStart + insertIdx * ATTRIBUTE_BYTE_SIZE;

                    byte[] result = new byte[xmlTree.length + ATTRIBUTE_BYTE_SIZE];
                    System.arraycopy(xmlTree, 0, result, 0, insertPos);

                    ByteBuffer attr = ByteBuffer.allocate(ATTRIBUTE_BYTE_SIZE)
                            .order(ByteOrder.LITTLE_ENDIAN);
                    attr.putInt(androidNsIdx);
                    attr.putInt(nameAttrIdx);
                    attr.putInt(proxyStringIdx);
                    attr.putShort((short) 0x08);
                    attr.put((byte) 0);
                    attr.put((byte) ATTR_TYPE_STRING);
                    attr.putInt(proxyStringIdx);
                    System.arraycopy(attr.array(), 0, result, insertPos, ATTRIBUTE_BYTE_SIZE);

                    System.arraycopy(xmlTree, insertPos, result,
                            insertPos + ATTRIBUTE_BYTE_SIZE,
                            xmlTree.length - insertPos);

                    ByteBuffer patcher = wrap(result);
                    patcher.position(attrCountPos);
                    patcher.putShort((short) (attrCount + 1));
                    patcher.position(chunkPos + 4);
                    patcher.putInt(chunkSize + ATTRIBUTE_BYTE_SIZE);

                    return result;
                }
            }

            buf.position(chunkPos + chunkSize);
        }

        return xmlTree;
    }

    private static int getIntAt(byte[] data, int offset) {
        return (data[offset] & 0xFF)
             | ((data[offset + 1] & 0xFF) << 8)
             | ((data[offset + 2] & 0xFF) << 16)
             | ((data[offset + 3] & 0xFF) << 24);
    }

    // ── 属性移除 ──────────────────────────────────────────────────

    /**
     * 从指定标签中移除某个属性（按 name 字符串索引匹配）。
     * 返回删除 20 字节后的新 xmlTree。
     */
    private byte[] removeAttribute(byte[] xmlTree, int applicationIdx, int attrNameIdx) {
        ByteBuffer buf = wrap(xmlTree);

        while (buf.remaining() >= 8) {
            int chunkPos  = buf.position();
            int chunkType = buf.getInt();
            int chunkSize = buf.getInt();
            if (chunkSize < 8 || chunkPos + chunkSize > xmlTree.length) break;

            if (chunkType == CHUNK_START_TAG) {
                buf.getInt(); // lineNumber
                buf.getInt(); // comment
                buf.getInt(); // namespaceUri
                int tagName = buf.getInt();

                if (tagName == applicationIdx) {
                    buf.getShort(); // attributeStart
                    buf.getShort(); // attributeSize
                    int attrCountPos = buf.position();
                    int attrCount = buf.getShort() & 0xFFFF;
                    buf.getShort(); // idIndex
                    buf.getShort(); // classIndex
                    buf.getShort(); // styleIndex

                    int attrsStart = buf.position();

                    for (int i = 0; i < attrCount; i++) {
                        int attrOff = attrsStart + i * ATTRIBUTE_BYTE_SIZE;
                        int nameIdx = getIntAt(xmlTree, attrOff + 4);
                        if (nameIdx == attrNameIdx) {
                            byte[] result = new byte[xmlTree.length - ATTRIBUTE_BYTE_SIZE];
                            System.arraycopy(xmlTree, 0, result, 0, attrOff);
                            System.arraycopy(xmlTree, attrOff + ATTRIBUTE_BYTE_SIZE,
                                    result, attrOff,
                                    xmlTree.length - attrOff - ATTRIBUTE_BYTE_SIZE);

                            ByteBuffer patcher = wrap(result);
                            patcher.position(attrCountPos);
                            patcher.putShort((short) (attrCount - 1));
                            patcher.position(chunkPos + 4);
                            patcher.putInt(chunkSize - ATTRIBUTE_BYTE_SIZE);

                            System.out.printf("[ManifestEditor] 已移除 <application> 的 appComponentFactory 属性%n");
                            return result;
                        }
                    }
                    return xmlTree;
                }
            }

            buf.position(chunkPos + chunkSize);
        }
        return xmlTree;
    }

    // ── ResourceID 解析 ─────────────────────────────────────────

    /**
     * 从 StringPool 之后的字节流中解析 ResourceID chunk。
     */
    private int[] parseResourceIds(byte[] data) {
        if (data.length < 8) return new int[0];
        ByteBuffer buf = wrap(data);
        int type = buf.getInt();
        int size = buf.getInt();
        if (type != CHUNK_RESOURCE_IDS || size < 8) return new int[0];
        int count = (size - 8) / 4;
        return readIntArray(buf, count);
    }

    /**
     * 优先通过 ResourceID (0x01010003) 定位 "name" 属性的字符串索引，
     * 回退到字符串匹配。
     */
    private int resolveNameAttrIndex(List<String> strings, int[] resourceIds) {
        for (int i = 0; i < resourceIds.length && i < strings.size(); i++) {
            if (resourceIds[i] == RES_ANDROID_NAME) {
                return i;
            }
        }
        return indexOfString(strings, ATTR_NAME);
    }

    /**
     * 在 ResourceID 表中查找指定资源 ID 对应的字符串索引，未找到返回 -1。
     */
    private int resolveResIdIndex(int[] resourceIds, int targetResId) {
        for (int i = 0; i < resourceIds.length; i++) {
            if (resourceIds[i] == targetResId) {
                return i;
            }
        }
        return -1;
    }

    // ── StringPool 重建 ─────────────────────────────────────────

    private byte[] rebuildStringPool(List<String> strings, boolean isUtf8, int flags,
                                     int styleCount, int[] styleOffsets,
                                     byte[] rawStyleData) throws IOException {

        int stringCount = strings.size();

        // 编码所有字符串
        List<byte[]> encodedStrings = new ArrayList<>(stringCount);
        for (String s : strings) {
            encodedStrings.add(isUtf8 ? encodeUtf8(s) : encodeUtf16(s));
        }

        // 构建偏移表 & 字符串数据区
        int headerSize = 28; // 7 × 4
        int offsetsSize = 4 * stringCount + 4 * styleCount;
        int stringsStartOffset = headerSize + offsetsSize;

        int[] newStringOffsets = new int[stringCount];
        ByteArrayOutputStream stringDataBuf = new ByteArrayOutputStream();
        for (int i = 0; i < stringCount; i++) {
            newStringOffsets[i] = stringDataBuf.size();
            stringDataBuf.write(encodedStrings.get(i));
        }
        byte[] stringData = stringDataBuf.toByteArray();

        // 4 字节对齐
        int padding = (4 - (stringData.length % 4)) % 4;
        int alignedStringDataLen = stringData.length + padding;

        // 计算 style 部分
        int newStylesOffset = 0;
        int styleDataLen = 0;
        if (styleCount > 0 && rawStyleData != null) {
            newStylesOffset = stringsStartOffset + alignedStringDataLen;
            styleDataLen = rawStyleData.length;
        }

        int chunkSize = stringsStartOffset + alignedStringDataLen + styleDataLen;

        // 写入 chunk
        byte[] chunk = new byte[chunkSize];
        ByteBuffer out = wrap(chunk);
        out.putInt(CHUNK_STRING_POOL);
        out.putInt(chunkSize);
        out.putInt(stringCount);
        out.putInt(styleCount);
        out.putInt(flags);
        out.putInt(stringsStartOffset);
        out.putInt(newStylesOffset);

        for (int off : newStringOffsets) out.putInt(off);
        if (styleOffsets != null) {
            for (int off : styleOffsets) out.putInt(off);
        }

        out.put(stringData);
        for (int i = 0; i < padding; i++) out.put((byte) 0);

        if (rawStyleData != null && styleDataLen > 0) {
            out.put(rawStyleData);
        }

        return chunk;
    }

    // ── 字符串编解码 ────────────────────────────────────────────

    /** 读取 AXML UTF-16LE 字符串 */
    private String decodeUtf16(ByteBuffer buf) {
        int charCount = buf.getShort() & 0xFFFF;
        if ((charCount & 0x8000) != 0) {
            int high = charCount & 0x7FFF;
            int low  = buf.getShort() & 0xFFFF;
            charCount = (high << 16) | low;
        }
        char[] chars = new char[charCount];
        for (int i = 0; i < charCount; i++) {
            chars[i] = buf.getChar(); // UTF-16LE
        }
        buf.getShort(); // null terminator
        return new String(chars);
    }

    /** 读取 AXML UTF-8 字符串 */
    private String decodeUtf8(ByteBuffer buf) {
        int charCount = readVarint(buf);
        int byteCount = readVarint(buf);
        byte[] bytes = new byte[byteCount];
        buf.get(bytes);
        buf.get(); // null terminator
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** 编码为 AXML UTF-16LE 格式 */
    private byte[] encodeUtf16(String s) {
        int charCount = s.length();
        ByteBuffer buf;
        if (charCount >= 0x8000) {
            buf = ByteBuffer.allocate(4 + charCount * 2 + 2).order(ByteOrder.LITTLE_ENDIAN);
            buf.putShort((short) (((charCount >> 16) & 0x7FFF) | 0x8000));
            buf.putShort((short) (charCount & 0xFFFF));
        } else {
            buf = ByteBuffer.allocate(2 + charCount * 2 + 2).order(ByteOrder.LITTLE_ENDIAN);
            buf.putShort((short) charCount);
        }
        for (int i = 0; i < charCount; i++) {
            buf.putChar(s.charAt(i)); // UTF-16LE via LITTLE_ENDIAN
        }
        buf.putShort((short) 0); // null terminator
        return buf.array();
    }

    /** 编码为 AXML UTF-8 格式 */
    private byte[] encodeUtf8(String s) {
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        int charCount = s.length();
        int byteCount = utf8.length;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        writeVarint(bos, charCount);
        writeVarint(bos, byteCount);
        bos.write(utf8, 0, utf8.length);
        bos.write(0); // null terminator
        return bos.toByteArray();
    }

    // ── 工具方法 ────────────────────────────────────────────────

    private static ByteBuffer wrap(byte[] data) {
        return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static int[] readIntArray(ByteBuffer buf, int count) {
        int[] arr = new int[count];
        for (int i = 0; i < count; i++) arr[i] = buf.getInt();
        return arr;
    }

    private static int readVarint(ByteBuffer buf) {
        int first = buf.get() & 0xFF;
        if ((first & 0x80) != 0) {
            int second = buf.get() & 0xFF;
            return ((first & 0x7F) << 8) | second;
        }
        return first;
    }

    private static void writeVarint(ByteArrayOutputStream bos, int value) {
        if (value >= 0x80) {
            bos.write(((value >> 8) & 0x7F) | 0x80);
            bos.write(value & 0xFF);
        } else {
            bos.write(value & 0x7F);
        }
    }

    private static int indexOfString(List<String> list, String target) {
        for (int i = 0; i < list.size(); i++) {
            if (target.equals(list.get(i))) return i;
        }
        return -1;
    }
}
