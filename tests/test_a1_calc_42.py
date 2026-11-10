"""§10.1 计算逻辑 4.2 优惠叠加/门槛绕过 检测能力测试。

验证 a1_calculation_logic_analyzer 对「优惠叠加 + 客户端自报门槛且服务端未重算」的识别，
并确认：带服务端重算的写法不被误报、普通 4.1 数量篡改仍走通用分支。
"""
from src.agents.a1_calculation_logic_analyzer import analyze_file


# 4.2 漏洞版：优惠叠加 + 客户端自报 total/threshold（方法体内 request.getParameter），无服务端重算
SAMPLE_42 = """
package com.quote.ctf_samples;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;

@RestController
@RequestMapping("/api/order")
public class CouponStackController {
    @PostMapping(value = "/checkout/coupons")
    public BigDecimal applyCoupons(HttpServletRequest request) {
        BigDecimal total = new BigDecimal(request.getParameter("total"));
        BigDecimal threshold = new BigDecimal(request.getParameter("threshold"));
        BigDecimal payable = total;
        String[] codes = request.getParameterValues("couponCodes");
        for (String code : codes) {
            BigDecimal off = couponService.valueOf(code);
            payable = payable.subtract(off);
        }
        if (payable.compareTo(threshold) >= 0) {
            return payable;
        }
        return payable;
    }
}
"""

# 4.2 安全版：叠加前先按购物车明文重算门槛/总价（服务端重算，含 recompute / verifyThreshold）
SAMPLE_42_SAFE = """
package com.quote.ctf_samples;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;

@RestController
public class SafeCouponController {
    @PostMapping(value = "/checkout/safe")
    public BigDecimal applyCoupons(HttpServletRequest request) {
        BigDecimal payable = recomputeTotal(request);
        verifyThreshold(request, payable);
        String[] codes = request.getParameterValues("couponCodes");
        for (String code : codes) {
            BigDecimal off = couponService.valueOf(code);
            payable = payable.subtract(off);
        }
        return payable;
    }
}
"""

# 4.1 通用数量篡改：方法体内 request.getParameter 取 quantity/price，参与 multiply 运算，无边界校验
SAMPLE_41 = """
package com.quote.ctf_samples;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;

@RestController
public class CheckoutController {
    @PostMapping(value = "/checkout")
    public BigDecimal checkout(HttpServletRequest request) {
        int quantity = Integer.parseInt(request.getParameter("quantity"));
        BigDecimal price = new BigDecimal(request.getParameter("price"));
        BigDecimal total = price.multiply(BigDecimal.valueOf(quantity));
        return total;
    }
}
"""


def test_42_discount_stacking_detected():
    hyps = analyze_file("CouponStackController.java", SAMPLE_42, "java")
    assert len(hyps) == 1
    h = hyps[0]
    assert h["category"] == "calculation_logic"
    assert h["subtype"] == "discount_stacking_threshold_bypass"
    assert h["function"] == "applyCoupons"


def test_42_safe_not_flagged():
    hyps = analyze_file("SafeCouponController.java", SAMPLE_42_SAFE, "java")
    assert hyps == []


def test_41_generic_still_detected():
    hyps = analyze_file("CheckoutController.java", SAMPLE_41, "java")
    assert len(hyps) == 1
    assert hyps[0]["category"] == "calculation_logic"
    assert "subtype" not in hyps[0]
