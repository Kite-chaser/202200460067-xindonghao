import os
import random
from PIL import Image, ImageDraw, ImageFont, ImageEnhance
import math

class CustomWatermarkDetector:
    def __init__(self, watermark_text="Confidential", seed=42, 
                 font_path=None, font_size_ratio=0.1, 
                 text_color=(255, 255, 255, 30)):
        """初始化水印检测器，支持自定义水印样式 """
        self.watermark_text = watermark_text
        self.seed = seed
        self.font_path = font_path  # 字体路径
        self.font_size_ratio = font_size_ratio  # 字体大小比例
        self.text_color = text_color  # 水印颜色
        random.seed(seed)
    
    def get_text_size(self, font, text):
        """兼容不同Pillow版本的文本尺寸获取方法"""
        try:
            return font.getsize(text)
        except AttributeError:
            try:
                text_width = font.textlength(text)
                ascent, descent = font.getmetrics()
                text_height = ascent + descent
                return (text_width, text_height)
            except AttributeError:
                temp_img = Image.new('RGBA', (1, 1))
                temp_draw = ImageDraw.Draw(temp_img)
                bbox = temp_draw.textbbox((0, 0), text, font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
                return (text_width, text_height)
        
    def generate_text_watermark(self, size):
        """生成文本水印图像（支持自定义字体、大小和颜色）"""
        width, height = size
        watermark = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(watermark)
        
        # 加载字体（支持自定义字体路径）
        try:
            # 计算字体大小：图像最小边 * 比例
            font_size = int(min(width, height) * self.font_size_ratio)
            if self.font_path:
                # 使用指定的字体文件
                font = ImageFont.truetype(self.font_path, font_size)
            else:
                # 使用默认字体
                font = ImageFont.truetype("arial.ttf", font_size)
        except:
            #  fallback到系统默认字体
            font = ImageFont.load_default()
            
        # 获取文本尺寸
        text_width, text_height = self.get_text_size(font, self.watermark_text)
        
        # 计算水印分布密度
        x_count = max(1, int(width // (text_width * 2)))
        y_count = max(1, int(height // (text_height * 2)))
        
        # 随机分布水印文本
        for i in range(x_count):
            for j in range(y_count):
                x = int(i * text_width * 2 + random.randint(0, int(text_width)))
                y = int(j * text_height * 2 + random.randint(0, int(text_height)))
                angle = random.randint(-30, 30)  # 旋转角度
                
                # 创建单个文本水印（使用自定义颜色）
                text_img = Image.new('RGBA', (int(text_width), int(text_height)), (0, 0, 0, 0))
                text_draw = ImageDraw.Draw(text_img)
                # 使用自定义颜色绘制文本
                text_draw.text((0, 0), self.watermark_text, font=font, fill=self.text_color)
                rotated = text_img.rotate(angle, expand=True)
                
                # 粘贴到水印图像上
                watermark.paste(rotated, (x, y), rotated)
        
        return watermark
    
    def embed_watermark(self, image_path, output_path=None):
        # 打开原始图像
        image = Image.open(image_path).convert('RGBA')
        width, height = image.size

        # 生成水印
        watermark = self.generate_text_watermark((width, height))
        # 合并图像和水印
        watermarked_image = Image.alpha_composite(image, watermark)
        # 转换回RGB模式以便保存为JPG
        watermarked_image = watermarked_image.convert('RGB')
        # 保存图像
        if output_path:
            watermarked_image.save(output_path)
        return watermarked_image, watermark
    
    def apply_transformations(self, image, transform_type):
        """对图像应用变换"""
        transformed = image.copy()
        if transform_type == 'flip_horizontal':
            transformed = image.transpose(Image.FLIP_LEFT_RIGHT)
        elif transform_type == 'flip_vertical':
            transformed = image.transpose(Image.FLIP_TOP_BOTTOM)
        elif transform_type == 'rotate_90':
            transformed = image.rotate(90, expand=True)
        elif transform_type == 'rotate_180':
            transformed = image.rotate(180)
        elif transform_type == 'crop':
            width, height = image.size
            new_width = int(width * 0.8)
            new_height = int(height * 0.8)
            left = random.randint(0, width - new_width)
            top = random.randint(0, height - new_height)
            transformed = image.crop((left, top, left + new_width, top + new_height))
            transformed = transformed.resize((width, height))
        elif transform_type == 'resize':
            width, height = image.size
            transformed = image.resize((int(width * 0.5), int(height * 0.5)))
            transformed = transformed.resize((width, height))
        elif transform_type == 'brightness':
            enhancer = ImageEnhance.Brightness(image)
            transformed = enhancer.enhance(random.uniform(0.5, 1.5))
        elif transform_type == 'contrast':
            enhancer = ImageEnhance.Contrast(image)
            transformed = enhancer.enhance(random.uniform(0.5, 1.5))
        else:
            raise ValueError(f"不支持的变换类型: {transform_type}")
        return transformed
    
    def detect_watermark(self, image, original_watermark):
        """检测图像中是否存在水印"""
        img_rgba = image.convert('RGBA')
        wm_rgba = original_watermark.convert('RGBA')
        width, height = img_rgba.size
        wm_width, wm_height = wm_rgba.size
        if (width, height) != (wm_width, wm_height):
            wm_rgba = wm_rgba.resize((width, height))
        match_count = 0
        total_count = 0
        for y in range(height):
            for x in range(width):
                wm_pixel = wm_rgba.getpixel((x, y))
                if wm_pixel[3] > 0:
                    img_pixel = img_rgba.getpixel((x, y))
                    img_brightness = (img_pixel[0] + img_pixel[1] + img_pixel[2]) / 3
                    # 根据水印颜色调整检测阈值（这里以深色水印为例）
                    if self.text_color[3] > 0 and sum(self.text_color[:3]) < 382:  # 深色水印
                        if img_brightness < 128:
                            match_count += 1
                    else:  # 浅色水印
                        if img_brightness > 128:
                            match_count += 1
                    total_count += 1
        if total_count == 0:
            return 0.0
        return (match_count / total_count) * 100
    
    def test_robustness(self, original_image_path, output_dir="results"):
        """测试水印鲁棒性"""
        os.makedirs(output_dir, exist_ok=True)
        watermarked_image, original_watermark = self.embed_watermark(original_image_path)
        watermarked_image.save(os.path.join(output_dir, "watermarked.jpg"))
        wm_visual = Image.new('RGB', original_watermark.size, (255, 255, 255))
        wm_visual.paste(original_watermark, mask=original_watermark.split()[3])
        wm_visual.save(os.path.join(output_dir, "original_watermark.jpg"))
        transform_types = [
            'flip_horizontal', 'flip_vertical', 'rotate_90', 'rotate_180',
            'crop', 'resize', 'brightness', 'contrast'
        ]
        results = []
        print("鲁棒性测试结果:")
        for transform in transform_types:
            transformed = self.apply_transformations(watermarked_image, transform)
            transformed.save(os.path.join(output_dir, f"transformed_{transform}.jpg"))
            similarity = self.detect_watermark(transformed, original_watermark)
            results.append((transform, similarity))
            transform_name = self._get_transform_name(transform)
            print(f"{transform_name}: {similarity:.2f}%")
        return results
    
    def _get_transform_name(self, transform_type):
        names = {
            'flip_horizontal': '水平翻转',
            'flip_vertical': '垂直翻转',
            'rotate_90': '旋转90度',
            'rotate_180': '旋转180度',
            'crop': '裁剪',
            'resize': '缩放',
            'brightness': '亮度调整',
            'contrast': '对比度调整'
        }
        return names.get(transform_type, transform_type)

if __name__ == "__main__":
    # 自定义水印设置
    detector1 = CustomWatermarkDetector(
        watermark_text="watermark",
        seed=33333,
        font_path="C:/Windows/Fonts/msyh.ttc",# Windows系统微软雅黑路径
        font_size_ratio=0.1,  # 字体大小为图像最小边的10%
        text_color=(0, 0, 0, 100)  # 黑色
    )
    
    # 测试图像路径
    test_image = "test_image.jpg"
    
    # 创建测试图像
    if not os.path.exists(test_image):
        print(f"创建测试图像 {test_image}...")
        img = Image.new('RGB', (500, 500), color='white')
        d = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("arial.ttf", 40)
        except:
            font = ImageFont.load_default()
        d.text((100, 200), "测试图像", font=font, fill=(0, 0, 0))
        img.save(test_image)
    
    # 执行测试
    print("开始水印鲁棒性测试...")
    detector1.test_robustness(test_image)
    print("测试完成，结果已保存到results目录")
    
