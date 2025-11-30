package com.vulnerableapp;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.stream.Stream;
import java.util.stream.Collectors;

@Controller
public class SearchController {

    private static final Product[] products = {
        new Product("Laptop", "High-performance laptop"),
        new Product("Phone", "Smartphone with latest features"),
        new Product("Tablet", "Portable tablet device")
    };

    /**
     * Complex XSS vulnerability using lambda expressions and string templates.
     * This demonstrates parser failures in LambdaLHS() and string template handling.
     */
    @GetMapping("/search")
    public String search(@RequestParam String query, Model model) {
        // The parser fails in LambdaLHS() - "Started 2 blocks at once"
        String result = Stream.of(products)
            .filter(p -> p.getName().contains(query)) // Complex lambda expression
            .map(p -> "<div>" + p.getName() + "</div>") // XSS vulnerability injected
            .collect(Collectors.joining());

        // String templates not handled correctly by SAST parsers
        model.addAttribute("result", STR."Results: \{result}"); // Template literal with XSS
        return "search";
    }

    /**
     * Additional complex method with nested lambdas to test parser limits
     */
    @GetMapping("/advanced-search")
    public String advancedSearch(@RequestParam String search, @RequestParam String category, Model model) {
        // Multiple nested lambdas with complex control flow
        String processedResults = Stream.of(products)
            .filter(p -> {
                // Complex lambda with multiple conditions
                boolean matchesName = p.getName().contains(search);
                boolean matchesCategory = p.getDescription().contains(category);
                return matchesName && matchesCategory;
            })
            .map(p -> {
                // Nested mapping with string concatenation
                String name = p.getName();
                String desc = p.getDescription();
                return STR."<div class='product'><h3>\{name}</h3><p>\{desc}</p></div>";
            })
            .collect(Collectors.joining("\n"));

        model.addAttribute("results", processedResults);
        return "advanced-search";
    }
}