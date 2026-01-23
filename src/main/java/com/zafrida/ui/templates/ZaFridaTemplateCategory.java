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
    /** Android 模板分类 */
    ANDROID("Android"),
    /** iOS 模板分类 */
    IOS("iOS"),
    /** 用户自定义分类 */
    CUSTOM("Custom");

    /** 显示名称 */
    private final String displayName;

    /**
     * 构造函数。
     * @param displayName 显示名称
     */
    ZaFridaTemplateCategory(String displayName) {
        this.displayName = displayName;
    }

    /**
     * 获取显示名称。
     * @return 显示名称
     */
    public String getDisplayName() {
        return displayName;
    }
}
