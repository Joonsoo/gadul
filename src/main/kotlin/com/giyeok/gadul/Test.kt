package com.giyeok.gadul

import capstone.Capstone
import javafx.application.Application
import javafx.geometry.Orientation
import javafx.scene.Scene
import javafx.scene.control.SplitPane
import javafx.scene.control.TextArea
import javafx.scene.text.Font
import javafx.stage.Stage
import sun.plugin.dom.exception.InvalidStateException
import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile
import java.util.*

interface AnnotatableInputStream {
    fun pushContext(description: String)
    fun addCoverage(range: LongRange)
    fun popContext()

    fun setByteValue(v: Byte)
    fun setShortValue(v: Short)
    fun setIntValue(v: Int)
    fun setLongValue(v: Long)
    fun setBytesValue(v: ByteArray)
    fun setStringValue(v: String)

    var useBigEndian: Boolean
    fun useBigEndian(useBigEndian: Boolean) {
        this.useBigEndian = useBigEndian
    }

    fun readByte(): Byte
    fun read(): Byte = readByte()

    fun pos(): Long

    fun readFully(array: ByteArray)

    fun readFully(array: ByteArray, description: String) {
        pushContext(description)
        readFully(array)
        setBytesValue(array)
        popContext()
    }

    fun readByte(description: String): Byte {
        pushContext(description)
        val v = readByte()
        setByteValue(v)
        popContext()
        return v
    }

    fun readShort(): Short {
        val ch1 = this.read().toInt() and 255
        val ch2 = this.read().toInt() and 255
        return if (useBigEndian) ((ch1 shl 0) or (ch2 shl 8)).toShort() else ((ch1 shl 8) or (ch2 shl 0)).toShort()
    }

    fun readShort(description: String): Short {
        pushContext(description)
        val v = readShort()
        setShortValue(v)
        popContext()
        return v
    }

    fun readInt(): Int {
        val ch1 = this.read().toInt() and 255
        val ch2 = this.read().toInt() and 255
        val ch3 = this.read().toInt() and 255
        val ch4 = this.read().toInt() and 255
        return if (useBigEndian) {
            (ch1 shl 0) or (ch2 shl 8) or
                    (ch3 shl 16) or (ch4 shl 24)
        } else {
            (ch1 shl 24) or (ch2 shl 16) or
                    (ch3 shl 8) or (ch4 shl 0)
        }
    }

    fun readInt(description: String): Int {
        pushContext(description)
        val v = readInt()
        setIntValue(v)
        popContext()
        return v
    }

    fun readLong(): Long {
        val i1 = this.readInt().toLong() and 0xFFFFFFFFL
        val i2 = this.readInt().toLong() and 0xFFFFFFFFL
        return if (useBigEndian) (i1 shl 0) or (i2 shl 32) else (i1 shl 32) or (i2 shl 0)
    }

    fun readLong(description: String): Long {
        pushContext(description)
        val v = readLong()
        setLongValue(v)
        popContext()
        return v
    }
}

abstract class AnnotatedInputStream : AnnotatableInputStream {
    data class Coverage(val posSet: MutableList<LongRange>) {
        constructor() : this(mutableListOf<LongRange>())

        fun add(posRange: LongRange) {
            val cont = this.posSet.find { it.endInclusive + 1 == posRange.start }
            if (cont != null) {
                this.posSet.remove(cont)
                this.posSet.add(cont.first..posRange.endInclusive)
            } else {
                this.posSet.add(posRange)
            }
        }
    }

    data class Context(
            val parent: Context?,
            val children: MutableList<Context>,
            val description: String,
            var value: Any?,
            val coverage: Coverage) {

        fun augmentedValueString(): String =
                when (value) {
                    is Byte -> " 0x%x".format(value)
                    is Short -> " 0x%x".format(value)
                    is Int -> " 0x%x".format(value)
                    is Long -> " 0x%x".format(value)
                    is ByteArray -> Arrays.toString(value as ByteArray)
                    else -> ""
                }

        override fun toString(): String = "\"$description\" ($value${augmentedValueString()}}) @ $coverage"

        fun toFromRootString(): String {
            val stringBuilder = StringBuilder()
            fun traverse(context: Context, stringBuilder: StringBuilder): Int {
                return if (context.parent == null) 0 else {
                    val myDepth = traverse(context.parent, stringBuilder)
                    stringBuilder.append("  ".repeat(myDepth) + context.toString() + "\n")
                    myDepth + 1
                }
            }
            traverse(this, stringBuilder)
            return stringBuilder.toString()
        }

        fun toDownString(): String =
                toDownStringWithSelectionInfo().first

        fun toDownStringWithSelectionInfo(): Pair<String, Map<IntRange, Context>> {
            val stringBuilder = StringBuilder()
            val selectionInfo = mutableMapOf<IntRange, Context>()
            fun traverse(context: Context, depth: Int, stringBuilder: StringBuilder) {
                val start = stringBuilder.length
                stringBuilder.append("  ".repeat(depth) + context.toString() + "\n")
                selectionInfo[start until stringBuilder.length] = context
                context.children.forEach { traverse(it, depth + 1, stringBuilder) }
            }
            traverse(this, 0, stringBuilder)
            return Pair(stringBuilder.toString(), selectionInfo.toMap())
        }
    }

    // null means root
    private val root = Context(null, mutableListOf(), "Document", null, Coverage())
    private var currentContext: Context = root

    private val coverageMap = mutableMapOf<LongRange, List<Context>>()

    override fun pushContext(description: String) {
        val newContext = Context(currentContext, mutableListOf(), description, null, Coverage())
        currentContext.children.add(newContext)
        currentContext = newContext
    }

    override fun addCoverage(range: LongRange) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.coverage.add(range)
        coverageMap[range] = (coverageMap[range] ?: listOf()) + currentContext
    }

    override fun setByteValue(v: Byte) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.value = v
    }

    override fun setShortValue(v: Short) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.value = v
    }

    override fun setIntValue(v: Int) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.value = v
    }

    override fun setLongValue(v: Long) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.value = v
    }

    override fun setStringValue(v: String) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.value = v
    }

    override fun setBytesValue(v: ByteArray) {
        if (currentContext === root) {
            throw InvalidStateException("Context is at root")
        }
        currentContext.value = v
    }

    override fun popContext() {
        if (currentContext === root) {
            throw InvalidStateException("Already at root")
        }
        currentContext = currentContext.parent!!
    }

    fun treeText(): String = root.toDownString()
    fun treeTextWithSelectionInfo(): Pair<String, Map<IntRange, Context>> = root.toDownStringWithSelectionInfo()

    fun findCoverages(pos: Long): List<Context> {
        val contexts = coverageMap.filter { it.key.contains(pos) }.values
        return if (contexts.isEmpty()) listOf() else contexts.reduce { acc, list -> acc + list }
    }
}

class AnnotatedRandomAccessFileInputStream(val source: RandomAccessFile) : AnnotatedInputStream(), Closeable {
    override var useBigEndian: Boolean = true

    override fun readFully(array: ByteArray) {
        val start = pos()
        source.readFully(array)
        addCoverage(start until pos())
    }

    override fun readByte(): Byte {
        val start = pos()
        val v = source.readByte()
        addCoverage(start until pos())
        return v
    }

    override fun pos(): Long = source.filePointer

    fun seek(pos: Long) {
        source.seek(pos)
    }

    override fun close() {
        source.close()
    }
}

class ElfReader {
    fun readElf(input: AnnotatedRandomAccessFileInputStream) {
        input.pushContext("ELF")

        input.pushContext("ELF HEADER")
        input.pushContext("EIDENT")
        val magic = input.readInt("magic")
        val E_CLASS = input.readByte("E_CLASS")
        val EI_DATA = input.readByte("EI_DATA")
        input.useBigEndian(EI_DATA.toInt() == 1)
        val EI_VERSION = input.readByte("EI_VERSION")
        val EI_OSABI = input.readByte("EI_OSABI")
        val EI_ABIVERSION = input.readByte("EI_ABIVERSION")
        val EI_PAD = ByteArray(7)
        input.readFully(EI_PAD, "EI_PAD")
        val e_type = input.readShort("e_type")
        val e_machine = input.readShort("e_machine")
        val e_version = input.readInt("e_version")
        input.popContext()

        val e_entry = input.readLong("e_entry")
        val e_phoff = input.readLong("e_phoff")
        val e_shoff = input.readLong("e_shoff")
        val e_flags = input.readInt("e_flags")
        val e_ehsize = input.readShort("e_ehsize")
        val e_phentsize = input.readShort("e_phentsize")
        val e_phnum = input.readShort("e_phnum")
        val e_shentsize = input.readShort("e_shentsize")
        val e_shnum = input.readShort("e_shnum")
        val e_shstrndx = input.readShort("e_shstrndx")
        input.popContext()

        input.seek(e_phoff)
        fun readPh64(idx: Int) {
            input.pushContext("program header $idx")
            val p_type = input.readInt("p_type")
            val p_flags = input.readInt("p_flags")
            val p_offset = input.readLong("p_offset")
            val p_vaddr = input.readLong("p_vaddr")
            val p_paddr = input.readLong("p_paddr")
            val p_filesz = input.readLong("p_filesz")
            val p_memsz = input.readLong("p_memsz")
            val p_align = input.readLong("p_align")
            input.popContext()
        }
        input.pushContext("Program Headers")
        for (i in 0 until e_phnum) {
            readPh64(i)
        }
        input.popContext()

        input.seek(e_shoff)
        fun readSh64(idx: Int) {
            input.pushContext("section header $idx")
            val sh_name = input.readInt("sh_name")
            val sh_type = input.readInt("sh_type")
            val sh_flags = input.readLong("sh_flags")
            val sh_addr = input.readLong("sh_addr")
            val sh_offset = input.readLong("sh_offset")
            val sh_size = input.readLong("sh_size")
            val sh_link = input.readInt("sh_link")
            val sh_info = input.readInt("sh_info")
            val sh_addralign = input.readLong("sh_addralign")
            val sh_entsize = input.readLong("sh_entsize")
            input.popContext()
        }
        input.pushContext("Section Headers")
        for (i in 0 until e_shnum) {
            readSh64(i)
        }
        input.popContext()

        input.popContext()
    }
}

class HexViewApp : Application() {
    override fun start(primaryStage: Stage) {
        val file = RandomAccessFile(File("example/a.out"), "r")
        val input = AnnotatedRandomAccessFileInputStream(file)

        ElfReader().readElf(input)

        val font = Font.font("D2Coding")

        val hexTextArea = TextArea()
        hexTextArea.font = font

        val lines = mutableListOf<String>()
        file.seek(0)
        val oneline = ByteArray(16)
        var read = file.read(oneline)
        val onelineLength = 3 * 16 + 4 + 16
        while (read >= 0) {
            val readable = oneline.slice(0 until read).joinToString("") { b ->
                val v = b.toInt()
                when (v.toChar()) {
                    in 'a'..'z' -> "${v.toChar()}"
                    in 'A'..'Z' -> "${v.toChar()}"
                    in '0'..'9' -> "${v.toChar()}"
                    else -> "."
                }
            }
            val onelineText = oneline.slice(0 until read).joinToString(" ") { "%02x".format(it) } +
                    ("   ".repeat(16 - read)) + "    " + readable
            assert(onelineText.length == onelineLength)
            lines.add(onelineText)
            read = file.read(oneline)
        }
        val hexText = lines.joinToString("\n")

        hexTextArea.text = hexText

        val infoTextArea = TextArea()
        infoTextArea.font = font

        fun posToLineCol(pos: Long): Pair<Int, Int> {
            val line = pos / onelineLength
            val col = (pos % onelineLength) / 3
            return Pair(line.toInt(), col.toInt())
        }

        hexTextArea.selectionProperty().addListener { _, _, newValue ->
            val (line, col) = posToLineCol(newValue.start.toLong())
            val pos = (line.toLong() * 16) + col.toLong()
            val selectedLocation = "$line $col $pos(0x${"%x".format(pos)})"

            val covered = input.findCoverages(pos)
            val coveredString = covered.joinToString("\n") { context ->
                context.toFromRootString()
            }

            infoTextArea.text = "$selectedLocation\n\n" + coveredString
        }

        val treeTextArea = TextArea()
        treeTextArea.font = font

        val (treeText, selectionInfo) = input.treeTextWithSelectionInfo()
        treeTextArea.text = treeText
        treeTextArea.selectionProperty().addListener { _, _, newValue ->
            selectionInfo.keys.find { it.contains(newValue.start) }?.let { selected ->
                val pos = selectionInfo[selected]!!.coverage.posSet
                if (pos.isNotEmpty()) {
                    val (startLine, startCol) = Pair(pos[0].start / 16, pos[0].start % 16)
                    val (endLine, endCol) = Pair(pos[0].endInclusive / 16, (pos[0].endInclusive % 16))
                    hexTextArea.selectRange((startLine * onelineLength + startCol * 3).toInt(), (endLine * onelineLength + endCol * 3 + 2).toInt())
                }
            }
        }

        val rightPane = SplitPane(infoTextArea, treeTextArea)
        rightPane.orientation = Orientation.VERTICAL
        val layout = SplitPane(
                hexTextArea,
                rightPane
        )

        primaryStage.scene = Scene(layout)
        primaryStage.show()
    }
}

object Test {
    @JvmStatic
    fun main(args: Array<String>) {
//        val code = byteArrayOf(
//                0x31.toByte(), 0xed.toByte(), 0x49.toByte(), 0x89.toByte(), 0xd1.toByte(), 0x5e.toByte(), 0x48.toByte(), 0x89.toByte(), 0xe2.toByte(), 0x48.toByte(), 0x83.toByte(), 0xe4.toByte(), 0xf0.toByte(), 0x50.toByte(), 0x54.toByte(), 0x4c.toByte(),
//                0x8d.toByte(), 0x05.toByte(), 0x8a.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x48.toByte(), 0x8d.toByte(), 0x0d.toByte(), 0x13.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x48.toByte(), 0x8d.toByte(), 0x3d.toByte(),
//                0xe6.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0xff.toByte(), 0x15.toByte(), 0x86.toByte(), 0x0a.toByte(), 0x20.toByte(), 0x00.toByte(), 0xf4.toByte(), 0x0f.toByte(), 0x1f.toByte(), 0x44.toByte(), 0x00.toByte(), 0x00.toByte())
//        val cs = Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64)
//        val insns = cs.disasm(code, 0x1000)
//        for (insn in insns) {
//            println(String.format("0x%x:\t%s\t%s", insn.address, insn.mnemonic, insn.opStr))
//        }

        Application.launch(HexViewApp::class.java)
        System.exit(0)
    }
}