package com.zafrida.ui.templates;
/**
 * [枚举] 模板分类定义。
 * <p>
 * <strong>映射关系：</strong>
 * 对应 {@code ~/.zafrida/templates/} 下的子目录名称：
 * <ul>
 * <li>{@code ANDROID} -> {@code android/}</li>
 * <li>{@code IOS} -> {@code ios/}</li>
 * <li>{@code CUSTOM} -> {@code custom/} (用户自定义存放区)</li>
 * </ul>
 */
public enum ZaFridaTemplateCategory {
    ANDROID("Android"),
    IOS("iOS"),
    CUSTOM("Custom");

    private final String displayName;

    ZaFridaTemplateCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}