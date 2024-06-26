fn main() {
    {
        let mut s1 = String::from("hello");
        // s1はこのスコープで有効
        println!("{}", s1);

        let s2 = &mut s1; // s1の可変参照をs2に渡す

        // s2はこのスコープで有効
        s2.push_str(", world!");
        println!("{}", s2);

        println!("{}", s1); // s1はこのスコープで有効

    }
}
