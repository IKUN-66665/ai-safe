import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("=" * 40)
    print("AI-Safe")
    print("=" * 40)
    print("启动中...")
    print("先开Ollama: ollama pull deepseek-r1:7b")
    print("=" * 40)
    print()

    try:
        from ai_safe.safe_gui import main
        main()
    except Exception as e:
        print(f"启动失败: {e}")
        import traceback
        traceback.print_exc()
        input("按回车退出...")